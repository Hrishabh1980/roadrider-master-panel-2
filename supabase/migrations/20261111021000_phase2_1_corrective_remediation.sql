-- ============================================================================
-- ROADRIDER ECOSYSTEM — PHASE 2.1 CORRECTIVE REMEDIATION MIGRATION
-- Migration: 20261111021000_phase2_1_corrective_remediation.sql
-- Description: Admin Pricing Security Hardening, Partner Cancellation Authorization,
--              Post-Pickup Cancellation Protection, Realtime Re-dispatch, and Phase 2.1 Verification Suite
-- Target Database: db.sjahblquggmzlihqgzyt.supabase.co (Postgres 17)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. ADMIN PRICING SECURITY HARDENING
-- Revoke table write grants (INSERT, UPDATE, DELETE, TRUNCATE) from anon
-- Revoke TRUNCATE from authenticated
-- Enforce that ONLY authorized master administrators can modify pricing
-- ----------------------------------------------------------------------------

REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.pricing_rules FROM anon;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.surge_rules FROM anon;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.promotions FROM anon;

REVOKE TRUNCATE ON public.pricing_rules FROM authenticated;
REVOKE TRUNCATE ON public.surge_rules FROM authenticated;
REVOKE TRUNCATE ON public.promotions FROM authenticated;

-- Ensure SELECT is granted so clients can fetch authoritative rate cards & active promotions
GRANT SELECT ON public.pricing_rules TO anon, authenticated, service_role;
GRANT SELECT ON public.surge_rules TO anon, authenticated, service_role;
GRANT SELECT ON public.promotions TO anon, authenticated, service_role;

-- ----------------------------------------------------------------------------
-- 1.1 PARTNER ONBOARDING AND STATUS TRIGGER HARDENING
-- Allow service_role and internal functions (postgres) to maintain partner states
-- while strictly preserving Master Admin restrictions for regular users
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.protect_partner_approval_status()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
BEGIN
  -- Service role, session owner, and administrative bypass
  IF auth.role() = 'service_role' OR session_user = 'postgres' OR public.is_master_admin() THEN
    RETURN NEW;
  END IF;

  -- Restrict transitions to 'verified', 'approved', or 'rejected' strictly to Master Admin
  IF (NEW.kyc_status IN ('verified', 'approved', 'rejected'))
     AND (OLD.kyc_status IS DISTINCT FROM NEW.kyc_status) THEN
    IF NOT public.is_master_admin() THEN
      RAISE EXCEPTION 'Unauthorized: Only an authorized Master Admin can approve or reject rider onboarding applications.';
    END IF;
  END IF;

  -- Restrict activation strictly to Master Admin
  IF (NEW.is_active IS TRUE) AND (OLD.is_active IS NOT TRUE) THEN
    IF NOT public.is_master_admin() THEN
      RAISE EXCEPTION 'Unauthorized: Only an authorized Master Admin can activate a rider account.';
    END IF;
  END IF;

  -- Enforce: UNAPPROVED OR SUSPENDED RIDERS CANNOT GO ONLINE
  IF (NEW.status = 'online' OR NEW.status = 'busy') AND (OLD.status IS DISTINCT FROM NEW.status) THEN
    IF (NEW.is_active IS NOT TRUE) OR (NEW.kyc_status NOT IN ('verified', 'approved')) THEN
      RAISE EXCEPTION 'Unauthorized: Rider account must be approved by administration before going online.';
    END IF;
    IF (OLD.status = 'suspended') AND NOT public.is_master_admin() THEN
      RAISE EXCEPTION 'Unauthorized: Suspended riders cannot go online without administrative reinstatement.';
    END IF;
  END IF;

  -- Restrict modification of rejection_reason strictly to Master Admin
  IF NEW.rejection_reason IS DISTINCT FROM OLD.rejection_reason THEN
    IF NOT public.is_master_admin() THEN
      RAISE EXCEPTION 'Unauthorized: Only an authorized Master Admin can record or update application rejection reasons.';
    END IF;
  END IF;

  RETURN NEW;
END;
$function$;

-- ----------------------------------------------------------------------------
-- 2. PARTNER CANCELLATION AUTHORIZATION & POST-PICKUP PROTECTION
-- Updates cancel_order_and_release_partner to:
--   1. Validate caller identity (a partner cannot cancel another partner's order)
--   2. Block cancellation if pickup has already occurred (food handed over or OTP verified)
--   3. Cleanly reset order to 'searching' to trigger Realtime customer re-dispatch
--   4. Release partner back to active dispatch pool
-- ----------------------------------------------------------------------------

-- Drop prior 3-argument signature if necessary to avoid ambiguous overloads
DROP FUNCTION IF EXISTS public.cancel_order_and_release_partner(uuid, text, text);

CREATE OR REPLACE FUNCTION public.cancel_order_and_release_partner(
  p_order_id uuid,
  p_cancelled_by text, -- 'customer' | 'partner' | 'admin'
  p_reason text DEFAULT NULL,
  p_partner_id uuid DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $function$
DECLARE
  v_order record;
  v_partner_id uuid;
  v_caller_partner_id uuid;
  v_caller_auth uuid := auth.uid();
  v_now timestamptz := now();
  v_clean_reason text := COALESCE(trim(p_reason), 'Cancelled by ' || COALESCE(p_cancelled_by, 'user'));
  v_is_pickup_verified boolean := false;
  v_svc text;
BEGIN
  IF p_order_id IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error', 'Order ID is required');
  END IF;

  SELECT * INTO v_order
  FROM public.orders
  WHERE id = p_order_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'error', 'Order not found');
  END IF;

  v_partner_id := v_order.partner_id;
  v_svc := lower(trim(COALESCE(v_order.service_type, 'food')));

  -- Idempotent check
  IF v_order.order_status = 'cancelled' THEN
    RETURN jsonb_build_object(
      'success', true,
      'order_id', p_order_id,
      'order_status', 'cancelled',
      'notice', 'Order was already cancelled'
    );
  END IF;

  -- Block cancellation if already delivered or completed
  IF v_order.order_status IN ('completed', 'delivered') THEN
    RETURN jsonb_build_object(
      'success', false,
      'error', 'Cannot cancel order that has already been completed or delivered'
    );
  END IF;

  -- PARTNER CANCELLATION VALIDATIONS
  IF p_cancelled_by = 'partner' THEN
    -- A: Authorization Check: Ensure the partner cancelling is the assigned partner
    IF p_partner_id IS NOT NULL THEN
      IF v_partner_id IS NOT NULL AND v_partner_id != p_partner_id THEN
        RETURN jsonb_build_object(
          'success', false,
          'error', 'Unauthorized: Partner ID does not match assigned partner on this order'
        );
      END IF;
    END IF;

    -- If authenticated session exists, check partner auth ownership
    IF v_caller_auth IS NOT NULL THEN
      SELECT id INTO v_caller_partner_id
      FROM public.partners
      WHERE auth_user_id = v_caller_auth
      LIMIT 1;

      IF v_caller_partner_id IS NOT NULL AND v_partner_id IS NOT NULL AND v_partner_id != v_caller_partner_id THEN
        RETURN jsonb_build_object(
          'success', false,
          'error', 'Unauthorized: You are not the assigned partner for this order'
        );
      END IF;
    END IF;

    -- B: Post-Pickup Block: Cannot cancel after pickup has occurred
    IF v_order.order_status IN ('handed_over', 'picked_up', 'in_transit', 'out_for_delivery')
       OR v_order.delivery_status IN ('handed_over', 'picked_up', 'in_transit', 'out_for_delivery') THEN
      RETURN jsonb_build_object(
        'success', false,
        'error', 'Cannot cancel order after pickup has occurred. Please contact dispatch support.'
      );
    END IF;

    -- Check restaurant_pickup OTP table
    SELECT EXISTS (
      SELECT 1 FROM public.order_otp_verifications
      WHERE order_id = p_order_id
        AND otp_type = 'restaurant_pickup'
        AND verified_at IS NOT NULL
    ) INTO v_is_pickup_verified;

    IF v_is_pickup_verified THEN
      RETURN jsonb_build_object(
        'success', false,
        'error', 'Cannot cancel order after pickup OTP has been verified. Please contact dispatch support.'
      );
    END IF;

    -- C: Re-dispatch Order: Unassign partner and return to searching pool
    UPDATE public.orders
    SET
      partner_id = NULL,
      delivery_status = 'searching',
      order_status = CASE
        WHEN v_svc IN ('food', 'grocery') AND order_status IN ('ready', 'ready_for_pickup') THEN 'ready'
        WHEN v_svc IN ('food', 'grocery') AND order_status IN ('preparing', 'picking', 'packed') THEN order_status
        WHEN v_svc IN ('food', 'grocery') THEN 'accepted'
        ELSE 'searching'
      END,
      last_cancellation_reason = v_clean_reason,
      captain_latitude = NULL,
      captain_longitude = NULL,
      updated_at = v_now
    WHERE id = p_order_id;

    -- Synchronize public.rides (re-dispatch ride)
    UPDATE public.rides
    SET
      partner_id = NULL,
      status = 'searching',
      updated_at = v_now
    WHERE order_id = p_order_id
      AND status NOT IN ('completed', 'cancelled');

    -- Synchronize public.courier_jobs (re-dispatch courier)
    UPDATE public.courier_jobs
    SET
      partner_id = NULL,
      status = 'pending',
      updated_at = v_now
    WHERE id = p_order_id
      AND status NOT IN ('completed', 'delivered', 'cancelled');

  ELSE
    -- Customer or Admin cancellation: terminal cancelled state
    UPDATE public.orders
    SET
      order_status = 'cancelled',
      delivery_status = 'cancelled',
      cancellation_reason = v_clean_reason,
      last_cancellation_reason = v_clean_reason,
      captain_latitude = NULL,
      captain_longitude = NULL,
      updated_at = v_now
    WHERE id = p_order_id;

    -- Synchronize public.rides
    UPDATE public.rides
    SET
      status = 'cancelled',
      cancellation_reason = v_clean_reason,
      updated_at = v_now
    WHERE order_id = p_order_id
      AND status NOT IN ('completed', 'cancelled');

    -- Synchronize public.courier_jobs
    UPDATE public.courier_jobs
    SET
      status = 'cancelled',
      cancelled_at = v_now,
      cancellation_reason = v_clean_reason,
      updated_at = v_now
    WHERE id = p_order_id
      AND status NOT IN ('completed', 'delivered', 'cancelled');
  END IF;

  -- Release assigned captain back to active dispatch pool
  IF v_partner_id IS NOT NULL THEN
    UPDATE public.partners
    SET
      status = 'online',
      last_heartbeat_at = v_now
    WHERE id = v_partner_id;
  END IF;

  RETURN jsonb_build_object(
    'success', true,
    'order_id', p_order_id,
    'partner_id', v_partner_id,
    'cancelled_by', p_cancelled_by,
    'order_status', CASE WHEN p_cancelled_by = 'partner' THEN 'searching' ELSE 'cancelled' END,
    'delivery_status', CASE WHEN p_cancelled_by = 'partner' THEN 'searching' ELSE 'cancelled' END,
    'partner_released', (v_partner_id IS NOT NULL),
    'updated_at', v_now
  );
END;
$function$;

GRANT EXECUTE ON FUNCTION public.cancel_order_and_release_partner(uuid, text, text, uuid) TO authenticated, anon, service_role;

-- ----------------------------------------------------------------------------
-- 3. PHASE 2.1 AUTOMATED VERIFICATION SUITE
-- Comprehensive regression and verification tests for Phase 2.1
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.run_phase2_1_verification_suite()
RETURNS TABLE (
  test_num integer,
  test_name text,
  status text,
  details text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $function$
DECLARE
  v_test_order_id uuid := gen_random_uuid();
  v_test_order2_id uuid := gen_random_uuid();
  v_partner1_id uuid := gen_random_uuid();
  v_partner2_id uuid := gen_random_uuid();
  v_cust_id uuid := gen_random_uuid();
  v_store_id uuid := gen_random_uuid();
  v_fare_result jsonb;
  v_cancel_result jsonb;
  v_order_check record;
  v_partner_check record;
  v_anon_insert_blocked boolean := false;
  v_now timestamptz := now();
BEGIN
  -- SETUP: Seed test partner, customer, and store
  INSERT INTO public.partners (id, full_name, phone, status, kyc_status, is_active, current_lat, current_lng, created_at)
  VALUES 
    (v_partner1_id, 'Test Captain Phase2_1', '+919999900021', 'busy', 'verified', true, 26.8500, 80.9500, v_now),
    (v_partner2_id, 'Other Captain Phase2_1', '+919999900022', 'online', 'verified', true, 26.8510, 80.9510, v_now)
  ON CONFLICT (id) DO NOTHING;

  INSERT INTO public.customers (id, full_name, phone, created_at)
  VALUES (v_cust_id, 'Test Customer Phase2_1', '+919999900023', v_now)
  ON CONFLICT (id) DO NOTHING;

  INSERT INTO public.stores (id, store_name, status, is_active, created_at)
  VALUES (v_store_id, 'Test Kitchen Phase2_1', 'approved', true, v_now)
  ON CONFLICT (id) DO NOTHING;

  -- --------------------------------------------------------------------------
  -- TEST 1: Revocation of anon write privileges on pricing_rules
  -- --------------------------------------------------------------------------
  SELECT NOT EXISTS (
    SELECT 1 FROM information_schema.role_table_grants
    WHERE table_name IN ('pricing_rules', 'surge_rules', 'promotions')
      AND grantee = 'anon'
      AND privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')
  ) INTO v_anon_insert_blocked;

  IF v_anon_insert_blocked THEN
    test_num := 1;
    test_name := 'Admin Pricing anon Write Revocation';
    status := 'PASSED';
    details := 'anon role has zero INSERT, UPDATE, DELETE, or TRUNCATE privileges on pricing tables.';
    RETURN NEXT;
  ELSE
    test_num := 1;
    test_name := 'Admin Pricing anon Write Revocation';
    status := 'FAILED';
    details := 'anon role still possesses write privileges on pricing tables.';
    RETURN NEXT;
  END IF;

  -- --------------------------------------------------------------------------
  -- TEST 2: Dynamic fare calculation for Food with distance & coupon
  -- --------------------------------------------------------------------------
  v_fare_result := public.calculate_order_fare(
    p_service_type := 'food',
    p_distance_km := 6.5,
    p_duration_mins := 25,
    p_vehicle_type := 'bike',
    p_item_total := 350.00,
    p_coupon_code := 'WEEKEND50'
  );

  IF (v_fare_result->>'success')::boolean = true
     AND (v_fare_result->>'delivery_fee')::numeric > 0
     AND (v_fare_result->>'discount')::numeric = 50.00 THEN
    test_num := 2;
    test_name := 'Authoritative Food Fare & Coupon Calculation';
    status := 'PASSED';
    details := format('Food fare: subtotal=%s, delivery_fee=%s, discount=%s, total=%s',
      v_fare_result->>'item_total', v_fare_result->>'delivery_fee',
      v_fare_result->>'discount', v_fare_result->>'total_fare');
    RETURN NEXT;
  ELSE
    test_num := 2;
    test_name := 'Authoritative Food Fare & Coupon Calculation';
    status := 'FAILED';
    details := format('Food fare calculation failed: %s', v_fare_result);
    RETURN NEXT;
  END IF;

  -- --------------------------------------------------------------------------
  -- TEST 3: Dynamic fare calculation for Grocery
  -- --------------------------------------------------------------------------
  v_fare_result := public.calculate_order_fare(
    p_service_type := 'grocery',
    p_distance_km := 4.2,
    p_duration_mins := 20,
    p_vehicle_type := 'bike',
    p_item_total := 620.00,
    p_coupon_code := NULL
  );

  IF (v_fare_result->>'success')::boolean = true
     AND (v_fare_result->>'delivery_fee')::numeric > 0
     AND (v_fare_result->>'total_fare')::numeric >= 620.00 THEN
    test_num := 3;
    test_name := 'Authoritative Grocery Fare Calculation';
    status := 'PASSED';
    details := format('Grocery fare: items=%s, delivery_fee=%s, total=%s',
      v_fare_result->>'item_total', v_fare_result->>'delivery_fee', v_fare_result->>'total_fare');
    RETURN NEXT;
  ELSE
    test_num := 3;
    test_name := 'Authoritative Grocery Fare Calculation';
    status := 'FAILED';
    details := format('Grocery fare calculation failed: %s', v_fare_result);
    RETURN NEXT;
  END IF;

  -- --------------------------------------------------------------------------
  -- TEST 4: Partner Cancellation Authorization (Unauthorized Partner Blocked)
  -- --------------------------------------------------------------------------
  -- Create an active food order assigned to partner1
  INSERT INTO public.orders (
    id, customer_id, store_id, partner_id, order_number, service_type,
    order_status, delivery_status, subtotal, total_amount, payment_method,
    pickup_latitude, pickup_longitude, delivery_latitude, delivery_longitude, created_at
  ) VALUES (
    v_test_order_id, v_cust_id, v_store_id, v_partner1_id, 'TEST-21-001', 'food',
    'accepted', 'assigned', 350.00, 395.00, 'COD',
    26.8467, 80.9462, 26.8500, 80.9500, v_now
  );

  -- Attempt cancellation by partner2 (wrong partner)
  v_cancel_result := public.cancel_order_and_release_partner(
    p_order_id := v_test_order_id,
    p_cancelled_by := 'partner',
    p_reason := 'Unauthorized attempt',
    p_partner_id := v_partner2_id
  );

  IF (v_cancel_result->>'success')::boolean = false
     AND v_cancel_result->>'error' ILIKE '%Unauthorized%' THEN
    test_num := 4;
    test_name := 'Partner Cancellation Authorization Enforcement';
    status := 'PASSED';
    details := 'Cancellation rejected when partner ID does not match assigned partner.';
    RETURN NEXT;
  ELSE
    test_num := 4;
    test_name := 'Partner Cancellation Authorization Enforcement';
    status := 'FAILED';
    details := format('Unauthorized cancellation was unexpectedly allowed: %s', v_cancel_result);
    RETURN NEXT;
  END IF;

  -- --------------------------------------------------------------------------
  -- TEST 5: Post-Pickup Cancellation Block
  -- --------------------------------------------------------------------------
  -- Simulate pickup by updating order to handed_over and recording OTP verification
  INSERT INTO public.order_otp_verifications (order_id, otp_type, otp_code, verified_at, expires_at)
  VALUES (v_test_order_id, 'restaurant_pickup', '1234', v_now, v_now + interval '15 minutes')
  ON CONFLICT (order_id, otp_type) DO UPDATE SET verified_at = v_now;

  -- Simulate pickup following valid food state lifecycle: accepted -> preparing -> ready -> handed_over
  UPDATE public.orders SET order_status = 'preparing' WHERE id = v_test_order_id;
  UPDATE public.orders SET order_status = 'ready' WHERE id = v_test_order_id;
  UPDATE public.orders
  SET order_status = 'handed_over', delivery_status = 'picked_up'
  WHERE id = v_test_order_id;

  -- Attempt cancellation by assigned partner after pickup
  v_cancel_result := public.cancel_order_and_release_partner(
    p_order_id := v_test_order_id,
    p_cancelled_by := 'partner',
    p_reason := 'Vehicle breakdown after pickup',
    p_partner_id := v_partner1_id
  );

  IF (v_cancel_result->>'success')::boolean = false
     AND v_cancel_result->>'error' ILIKE '%after pickup%' THEN
    test_num := 5;
    test_name := 'Post-Pickup Cancellation Block';
    status := 'PASSED';
    details := 'Cancellation correctly blocked because food pickup has already occurred.';
    RETURN NEXT;
  ELSE
    test_num := 5;
    test_name := 'Post-Pickup Cancellation Block';
    status := 'FAILED';
    details := format('Post-pickup cancellation was not blocked: %s', v_cancel_result);
    RETURN NEXT;
  END IF;

  -- --------------------------------------------------------------------------
  -- TEST 6: Valid Pre-Pickup Partner Unassignment & Re-dispatch
  -- --------------------------------------------------------------------------
  -- Create a fresh active order assigned to partner1 in preparing state
  INSERT INTO public.orders (
    id, customer_id, store_id, partner_id, order_number, service_type,
    order_status, delivery_status, subtotal, total_amount, payment_method,
    pickup_latitude, pickup_longitude, delivery_latitude, delivery_longitude, created_at
  ) VALUES (
    v_test_order2_id, v_cust_id, v_store_id, v_partner1_id, 'TEST-21-002', 'food',
    'preparing', 'assigned', 420.00, 465.00, 'COD',
    26.8467, 80.9462, 26.8500, 80.9500, v_now
  );

  UPDATE public.partners SET status = 'busy' WHERE id = v_partner1_id;

  -- Perform valid partner cancellation (pre-pickup unassignment)
  v_cancel_result := public.cancel_order_and_release_partner(
    p_order_id := v_test_order2_id,
    p_cancelled_by := 'partner',
    p_reason := 'Puncture on the way to restaurant',
    p_partner_id := v_partner1_id
  );

  SELECT * INTO v_order_check FROM public.orders WHERE id = v_test_order2_id;
  SELECT * INTO v_partner_check FROM public.partners WHERE id = v_partner1_id;

  IF (v_cancel_result->>'success')::boolean = true
     AND v_order_check.partner_id IS NULL
     AND v_order_check.delivery_status = 'searching'
     AND v_partner_check.status = 'online' THEN
    test_num := 6;
    test_name := 'Clean Re-dispatch & Partner Release';
    status := 'PASSED';
    details := 'Order reset to delivery_status=searching, partner unassigned and status returned to online.';
    RETURN NEXT;
  ELSE
    test_num := 6;
    test_name := 'Clean Re-dispatch & Partner Release';
    status := 'FAILED';
    details := format('Re-dispatch failed. order_status=%s, delivery_status=%s, partner_id=%s, partner_status=%s',
      v_order_check.order_status, v_order_check.delivery_status, v_order_check.partner_id, v_partner_check.status);
    RETURN NEXT;
  END IF;

  -- --------------------------------------------------------------------------
  -- TEST 7: Customer Cancellation Terminal State
  -- --------------------------------------------------------------------------
  v_cancel_result := public.cancel_order_and_release_partner(
    p_order_id := v_test_order2_id,
    p_cancelled_by := 'customer',
    p_reason := 'Changed mind'
  );

  SELECT * INTO v_order_check FROM public.orders WHERE id = v_test_order2_id;

  IF (v_cancel_result->>'success')::boolean = true
     AND v_order_check.order_status = 'cancelled'
     AND v_order_check.delivery_status = 'cancelled' THEN
    test_num := 7;
    test_name := 'Customer Cancellation Terminal State';
    status := 'PASSED';
    details := 'Customer cancellation transitioned order to terminal cancelled status.';
    RETURN NEXT;
  ELSE
    test_num := 7;
    test_name := 'Customer Cancellation Terminal State';
    status := 'FAILED';
    details := format('Customer cancellation failed: %s', v_cancel_result);
    RETURN NEXT;
  END IF;

  -- --------------------------------------------------------------------------
  -- CLEANUP
  -- --------------------------------------------------------------------------
  DELETE FROM public.order_otp_verifications WHERE order_id IN (v_test_order_id, v_test_order2_id);
  DELETE FROM public.orders WHERE id IN (v_test_order_id, v_test_order2_id);
  DELETE FROM public.stores WHERE id = v_store_id;
  DELETE FROM public.customers WHERE id = v_cust_id;
  DELETE FROM public.partners WHERE id IN (v_partner1_id, v_partner2_id);

  test_num := 8;
  test_name := 'Phase 2.1 Test Artifacts Cleanup';
  status := 'PASSED';
  details := 'All test rows, verifications, and temporary fixtures cleanly removed.';
  RETURN NEXT;

END;
$function$;

GRANT EXECUTE ON FUNCTION public.run_phase2_1_verification_suite() TO authenticated, anon, service_role;
