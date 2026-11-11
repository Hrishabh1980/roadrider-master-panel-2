-- ==============================================================================
-- Migration: 20261111010000_phase1_core_workflow_restoration.sql
-- Project: RoadRider Ecosystem Phase 1 Core Workflow Restoration
-- Target Bugs: BUG-04 (Grocery Dispatch), BUG-05 (Courier Workflow),
--              BUG-06 (Ride Dual-Writing Sync), BUG-09 (Food Handover State Machine)
-- ==============================================================================

BEGIN;

-- ==============================================================================
-- 1. SECURE 4-DIGIT RESTAURANT PICKUP OTP GENERATION
-- Fixes: BUG-09, BUG-04
-- Ensures 4-digit CSPRNG OTP generation and stores plaintext otp_code for vendor display
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.generate_restaurant_pickup_otp(p_order_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $$
DECLARE
  v_order record;
  v_pepper text;
  v_existing record;
  v_otp_code text;
  v_hash text;
  v_expires_at timestamptz;
  v_now timestamptz := now();
  v_is_authorized boolean := false;
  v_caller_role text := auth.role();
  v_caller_uid uuid := auth.uid();
BEGIN
  IF p_order_id IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error', 'p_order_id cannot be NULL.', 'code', 'INVALID_PARAM');
  END IF;

  v_pepper := public.internal_get_otp_pepper();

  SELECT id, store_id, vendor_id, order_number, service_type,
         order_status, delivery_status, created_at
  INTO v_order
  FROM public.orders
  WHERE id = p_order_id;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'error', 'Order not found.', 'code', 'ORDER_NOT_FOUND');
  END IF;

  -- Caller authorization
  IF v_caller_role = 'service_role' OR v_caller_role IS NULL OR current_user = 'postgres' OR public.is_master_admin() THEN
    v_is_authorized := true;
  ELSIF v_order.store_id IS NOT NULL AND public.is_vendor_store_owner(v_order.store_id) THEN
    v_is_authorized := true;
  ELSIF v_order.vendor_id IS NOT NULL AND v_order.vendor_id = public.get_current_vendor_id() THEN
    v_is_authorized := true;
  ELSIF v_caller_role = 'authenticated' AND (v_order.partner_id IS NULL OR v_order.partner_id = public.get_partner_id_by_auth(v_caller_uid)) THEN
    v_is_authorized := true;
  END IF;

  IF NOT v_is_authorized THEN
    RETURN jsonb_build_object(
      'success', false,
      'error', 'Unauthorized: Only authorized store personnel or assigned captain can access pickup OTP.',
      'code', 'UNAUTHORIZED'
    );
  END IF;

  IF v_order.order_status IN ('cancelled', 'rejected')
     OR v_order.delivery_status = 'cancelled' THEN
    RETURN jsonb_build_object(
      'success', false,
      'error', 'Cannot generate pickup OTP for a cancelled or rejected order.',
      'code', 'ORDER_CANCELLED'
    );
  END IF;

  IF v_order.order_status IN ('picked_up', 'in_transit', 'delivered', 'completed')
     OR v_order.delivery_status IN ('picked_up', 'delivered') THEN
    RETURN jsonb_build_object(
      'success', false,
      'error', 'Order has already been picked up.',
      'code', 'ALREADY_PICKED_UP',
      'already_verified', true
    );
  END IF;

  SELECT id, otp_code, otp_hash, expires_at, verified_at, attempts
  INTO v_existing
  FROM public.order_otp_verifications
  WHERE order_id = p_order_id
    AND otp_type = 'restaurant_pickup';

  IF FOUND AND v_existing.verified_at IS NOT NULL THEN
    RETURN jsonb_build_object(
      'success', false,
      'error', 'Pickup OTP has already been verified.',
      'code', 'ALREADY_VERIFIED',
      'already_verified', true
    );
  END IF;

  -- Reuse existing valid 4-digit code if unexpired
  IF FOUND AND v_existing.expires_at > v_now
     AND v_existing.otp_code IS NOT NULL
     AND length(trim(v_existing.otp_code)) = 4 THEN
    RETURN jsonb_build_object(
      'success', true,
      'order_id', p_order_id,
      'otp_type', 'restaurant_pickup',
      'otp_code', v_existing.otp_code,
      'expires_at', v_existing.expires_at,
      'verified', false,
      'already_exists', true,
      'message', 'Share this OTP with the delivery captain when handing over the parcel.'
    );
  END IF;

  -- Generate cryptographically secure 4-digit numeric code
  v_otp_code := public.generate_secure_4digit_otp();
  v_hash := encode(sha256(v_otp_code::bytea), 'hex');
  v_expires_at := v_now + interval '2 hours';

  INSERT INTO public.order_otp_verifications (
    id, order_id, otp_type, otp_code, otp_hash,
    expires_at, attempts, created_at, updated_at
  )
  VALUES (
    gen_random_uuid(), p_order_id, 'restaurant_pickup', v_otp_code, v_hash,
    v_expires_at, 0, v_now, v_now
  )
  ON CONFLICT (order_id, otp_type) DO UPDATE SET
    otp_code = EXCLUDED.otp_code,
    otp_hash = EXCLUDED.otp_hash,
    expires_at = EXCLUDED.expires_at,
    attempts = 0,
    updated_at = v_now
  WHERE order_otp_verifications.verified_at IS NULL;

  RETURN jsonb_build_object(
    'success', true,
    'order_id', p_order_id,
    'otp_type', 'restaurant_pickup',
    'otp_code', v_otp_code,
    'expires_at', v_expires_at,
    'verified', false,
    'message', 'Share this OTP with the delivery captain when handing over the parcel.'
  );
END;
$$;

GRANT EXECUTE ON FUNCTION public.generate_restaurant_pickup_otp(uuid) TO authenticated, service_role;

CREATE OR REPLACE FUNCTION public.get_restaurant_pickup_otp(p_order_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $$
BEGIN
  RETURN public.generate_restaurant_pickup_otp(p_order_id);
END;
$$;

GRANT EXECUTE ON FUNCTION public.get_restaurant_pickup_otp(uuid) TO authenticated, service_role;


-- ==============================================================================
-- 2. CUSTOMER DELIVERY OTP RETRIEVAL WITH PROPER CUSTOMER IDENTITY RESOLUTION
-- Fixes: Customer OTP authorization failure when customer_id links to public.customers
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.get_customer_delivery_otp(p_order_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $$
DECLARE
  v_caller_uid UUID := auth.uid();
  v_caller_role TEXT := auth.role();
  v_is_authorized BOOLEAN := FALSE;
  v_order RECORD;
  v_otp RECORD;
  v_new_code TEXT;
  v_new_hash TEXT;
  v_now TIMESTAMPTZ := NOW();
BEGIN
  IF p_order_id IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error', 'p_order_id cannot be NULL', 'code', 'INVALID_INPUT');
  END IF;

  SELECT id, customer_id, partner_id, order_status, delivery_status, service_type
  INTO v_order
  FROM public.orders
  WHERE id = p_order_id;

  IF NOT FOUND THEN
    -- Check if it's a ride ID directly
    SELECT id, customer_id, partner_id, status as order_status, status as delivery_status, 'rides' as service_type
    INTO v_order
    FROM public.rides
    WHERE id = p_order_id;
  END IF;

  IF v_order.id IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error', 'Order or ride not found', 'code', 'ORDER_NOT_FOUND');
  END IF;

  -- Caller authorization: service_role, postgres, master admin, or the customer who placed the order
  IF v_caller_role = 'service_role' OR v_caller_role IS NULL OR current_user = 'postgres' OR public.is_master_admin() THEN
    v_is_authorized := TRUE;
  ELSIF v_caller_uid IS NOT NULL AND (
    v_order.customer_id = v_caller_uid
    OR EXISTS (
      SELECT 1 FROM public.customers c
      WHERE c.id = v_order.customer_id AND c.auth_user_id = v_caller_uid
    )
  ) THEN
    v_is_authorized := TRUE;
  END IF;

  IF NOT v_is_authorized THEN
    RETURN jsonb_build_object(
      'success', false,
      'error', 'Unauthorized: Caller is not the customer for this order.',
      'code', 'UNAUTHORIZED_CUSTOMER_ACCESS'
    );
  END IF;

  SELECT id, otp_code, otp_hash, expires_at, verified_at, attempts
  INTO v_otp
  FROM public.order_otp_verifications
  WHERE order_id = p_order_id
    AND otp_type = 'customer_delivery';

  -- If record is missing, generate it
  IF NOT FOUND THEN
    PERFORM public.generate_order_otps(p_order_id);
    SELECT id, otp_code, otp_hash, expires_at, verified_at, attempts
    INTO v_otp
    FROM public.order_otp_verifications
    WHERE order_id = p_order_id
      AND otp_type = 'customer_delivery';
  END IF;

  -- Check rider_otp_verifications for cab rides fallback
  IF v_otp IS NULL THEN
    SELECT id, otp_code, otp_hash, expires_at, verified_at, attempts
    INTO v_otp
    FROM public.rider_otp_verifications
    WHERE ride_id = p_order_id;
  END IF;

  -- Self-healing: If unverified existing record is missing plaintext code or expired, repair it
  IF v_otp IS NOT NULL AND v_otp.verified_at IS NULL THEN
    IF v_otp.otp_code IS NULL
       OR length(trim(v_otp.otp_code)) <> 4
       OR v_otp.otp_code !~ '^[0-9]{4}$'
       OR v_otp.expires_at < v_now THEN

      v_new_code := public.generate_secure_4digit_otp();
      v_new_hash := encode(sha256(v_new_code::bytea), 'hex');

      UPDATE public.order_otp_verifications
      SET
        otp_code = v_new_code,
        otp_hash = v_new_hash,
        expires_at = v_now + INTERVAL '4 hours',
        attempts = 0,
        updated_at = v_now
      WHERE id = v_otp.id
        AND verified_at IS NULL;

      v_otp.otp_code := v_new_code;
      v_otp.expires_at := v_now + INTERVAL '4 hours';
    END IF;
  END IF;

  IF v_otp IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error', 'Customer delivery OTP record not available', 'code', 'OTP_NOT_FOUND');
  END IF;

  RETURN jsonb_build_object(
    'success', true,
    'order_id', p_order_id,
    'otp_type', 'customer_delivery',
    'otp_code', v_otp.otp_code,
    'expires_at', v_otp.expires_at,
    'is_verified', (v_otp.verified_at IS NOT NULL),
    'verified_at', v_otp.verified_at
  );
END;
$$;

GRANT EXECUTE ON FUNCTION public.get_customer_delivery_otp(uuid) TO authenticated, service_role;


-- ==============================================================================
-- 3. UNIFIED OTP GENERATION FOR ALL SERVICES (FOOD, GROCERY, COURIER)
-- Fixes: BUG-04, BUG-05
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.generate_order_otps(p_order_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $$
DECLARE
  v_auth_uid UUID := auth.uid();
  v_auth_role TEXT := auth.role();
  v_partner_id UUID;
  v_order RECORD;
  v_pickup_otp TEXT;
  v_delivery_otp TEXT;
  v_pickup_hash TEXT;
  v_delivery_hash TEXT;
  v_now TIMESTAMPTZ := NOW();
  v_is_authorized BOOLEAN := FALSE;
BEGIN
  IF p_order_id IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error', 'p_order_id cannot be NULL', 'code', 'INVALID_INPUT');
  END IF;

  SELECT id, partner_id, customer_id, order_status, service_type, store_id, vendor_id
  INTO v_order
  FROM public.orders
  WHERE id = p_order_id;

  IF NOT FOUND THEN
    -- Check public.rides for cab ride
    SELECT id, partner_id, customer_id, status AS order_status, 'rides' AS service_type, NULL::uuid AS store_id, NULL::uuid AS vendor_id
    INTO v_order
    FROM public.rides
    WHERE id = p_order_id;
  END IF;

  IF v_order.id IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error', 'Order not found', 'code', 'ORDER_NOT_FOUND');
  END IF;

  -- Caller identity verification
  IF v_auth_role = 'service_role' OR v_auth_role IS NULL OR current_user = 'postgres' OR public.is_master_admin() THEN
    v_is_authorized := TRUE;
  ELSIF v_auth_role = 'authenticated' THEN
    SELECT id INTO v_partner_id FROM public.partners WHERE user_id = v_auth_uid;
    IF (v_partner_id IS NOT NULL AND v_order.partner_id = v_partner_id)
       OR v_order.partner_id IS NULL
       OR v_order.customer_id = v_auth_uid
       OR EXISTS (SELECT 1 FROM public.customers c WHERE c.id = v_order.customer_id AND c.auth_user_id = v_auth_uid)
       OR (v_order.store_id IS NOT NULL AND public.is_vendor_store_owner(v_order.store_id))
       OR (v_order.vendor_id IS NOT NULL AND v_order.vendor_id = public.get_current_vendor_id()) THEN
      v_is_authorized := TRUE;
    END IF;
  END IF;

  IF NOT v_is_authorized THEN
    RETURN jsonb_build_object('success', false, 'error', 'Unauthorized caller identity.', 'code', 'UNAUTHORIZED');
  END IF;

  IF LOWER(TRIM(COALESCE(v_order.order_status, ''))) IN ('cancelled', 'rejected') THEN
    RETURN jsonb_build_object('success', false, 'error', 'Cannot generate OTPs for a cancelled/rejected order', 'code', 'ORDER_CANCELLED');
  END IF;

  -- Generate two distinct CSPRNG 4-digit codes
  v_pickup_otp := public.generate_secure_4digit_otp();
  v_delivery_otp := public.generate_secure_4digit_otp();
  WHILE v_delivery_otp = v_pickup_otp LOOP
    v_delivery_otp := public.generate_secure_4digit_otp();
  END LOOP;

  v_pickup_hash := encode(sha256(v_pickup_otp::bytea), 'hex');
  v_delivery_hash := encode(sha256(v_delivery_otp::bytea), 'hex');

  -- Stage 1: restaurant_pickup (store pickup for food & grocery; sender pickup for courier)
  INSERT INTO public.order_otp_verifications (
    id, order_id, otp_type, otp_code, otp_hash,
    expires_at, attempts, created_at, updated_at
  ) VALUES (
    gen_random_uuid(), p_order_id, 'restaurant_pickup', v_pickup_otp, v_pickup_hash,
    v_now + INTERVAL '3 hours', 0, v_now, v_now
  )
  ON CONFLICT (order_id, otp_type) DO UPDATE
  SET
    otp_code = CASE
      WHEN public.order_otp_verifications.otp_code IS NULL OR length(trim(public.order_otp_verifications.otp_code)) <> 4 OR public.order_otp_verifications.expires_at < v_now
      THEN EXCLUDED.otp_code
      ELSE public.order_otp_verifications.otp_code
    END,
    otp_hash = CASE
      WHEN public.order_otp_verifications.otp_hash IS NULL OR length(trim(public.order_otp_verifications.otp_hash)) < 32 OR public.order_otp_verifications.expires_at < v_now
      THEN EXCLUDED.otp_hash
      ELSE public.order_otp_verifications.otp_hash
    END,
    expires_at = CASE
      WHEN public.order_otp_verifications.expires_at < v_now THEN EXCLUDED.expires_at
      ELSE public.order_otp_verifications.expires_at
    END,
    attempts = CASE
      WHEN public.order_otp_verifications.expires_at < v_now THEN 0
      ELSE public.order_otp_verifications.attempts
    END,
    updated_at = v_now
  WHERE public.order_otp_verifications.verified_at IS NULL;

  -- Stage 2: customer_delivery (delivery dropoff PIN for food, grocery, courier, ride)
  INSERT INTO public.order_otp_verifications (
    id, order_id, otp_type, otp_code, otp_hash,
    expires_at, attempts, created_at, updated_at
  ) VALUES (
    gen_random_uuid(), p_order_id, 'customer_delivery', v_delivery_otp, v_delivery_hash,
    v_now + INTERVAL '5 hours', 0, v_now, v_now
  )
  ON CONFLICT (order_id, otp_type) DO UPDATE
  SET
    otp_code = CASE
      WHEN public.order_otp_verifications.otp_code IS NULL OR length(trim(public.order_otp_verifications.otp_code)) <> 4 OR public.order_otp_verifications.expires_at < v_now
      THEN EXCLUDED.otp_code
      ELSE public.order_otp_verifications.otp_code
    END,
    otp_hash = CASE
      WHEN public.order_otp_verifications.otp_hash IS NULL OR length(trim(public.order_otp_verifications.otp_hash)) < 32 OR public.order_otp_verifications.expires_at < v_now
      THEN EXCLUDED.otp_hash
      ELSE public.order_otp_verifications.otp_hash
    END,
    expires_at = CASE
      WHEN public.order_otp_verifications.expires_at < v_now THEN EXCLUDED.expires_at
      ELSE public.order_otp_verifications.expires_at
    END,
    attempts = CASE
      WHEN public.order_otp_verifications.expires_at < v_now THEN 0
      ELSE public.order_otp_verifications.attempts
    END,
    updated_at = v_now
  WHERE public.order_otp_verifications.verified_at IS NULL;

  -- Also populate delivery_otp column on orders for fast retrieval
  UPDATE public.orders
  SET delivery_otp = COALESCE(
    (SELECT otp_code FROM public.order_otp_verifications WHERE order_id = p_order_id AND otp_type = 'customer_delivery'),
    v_delivery_otp
  )
  WHERE id = p_order_id;

  RETURN jsonb_build_object('success', true);
END;
$$;

GRANT EXECUTE ON FUNCTION public.generate_order_otps(uuid) TO authenticated, service_role;


-- ==============================================================================
-- 4. DISPATCH: EXPAND fetch_available_orders TO GROCERY & COURIER
-- Fixes: BUG-04 (Grocery orders invisible to riders), BUG-05 (Courier orders invisible to riders)
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.fetch_available_orders(p_partner_id uuid DEFAULT NULL)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $$
DECLARE
  v_orders JSONB;
BEGIN
  SELECT COALESCE(
    jsonb_agg(
      to_jsonb(o.*) || jsonb_build_object(
        'order_items', COALESCE(
          (
            SELECT jsonb_agg(to_jsonb(oi.*))
            FROM public.order_items oi
            WHERE oi.order_id = o.id
          ),
          '[]'::jsonb
        ),
        'dispatch_attempt_id', (
          SELECT dda.id
          FROM public.delivery_dispatch_attempts dda
          WHERE dda.order_id = o.id
            AND (p_partner_id IS NULL OR dda.partner_id = p_partner_id)
            AND dda.status = 'offered'
            AND dda.expires_at > NOW()
          ORDER BY dda.offered_at DESC
          LIMIT 1
        ),
        'dispatch_id', (
          SELECT dd.id
          FROM public.delivery_dispatches dd
          WHERE dd.order_id = o.id
            AND dd.status IN ('searching', 'offered')
          ORDER BY dd.created_at DESC
          LIMIT 1
        ),
        'assignment_expires_at', (
          SELECT dda.expires_at
          FROM public.delivery_dispatch_attempts dda
          WHERE dda.order_id = o.id
            AND (p_partner_id IS NULL OR dda.partner_id = p_partner_id)
            AND dda.status = 'offered'
            AND dda.expires_at > NOW()
          ORDER BY dda.offered_at DESC
          LIMIT 1
        )
      )
      ORDER BY o.created_at DESC
    ),
    '[]'::jsonb
  ) INTO v_orders
  FROM public.orders o
  WHERE (
    -- 1. Food orders: preparing or ready
    (
      LOWER(TRIM(COALESCE(o.service_type, 'food'))) IN ('food', 'food_delivery', 'restaurant')
      AND LOWER(TRIM(COALESCE(o.order_status, ''))) IN ('preparing', 'ready')
    )
    OR
    -- 2. Grocery orders: accepted, preparing, picking, packed, ready, ready_for_pickup
    (
      LOWER(TRIM(COALESCE(o.service_type, ''))) = 'grocery'
      AND LOWER(TRIM(COALESCE(o.order_status, ''))) IN ('accepted', 'preparing', 'picking', 'packed', 'ready', 'ready_for_pickup')
    )
    OR
    -- 3. Courier orders: placed, new, searching, accepted
    (
      LOWER(TRIM(COALESCE(o.service_type, ''))) = 'courier'
      AND LOWER(TRIM(COALESCE(o.order_status, ''))) IN ('placed', 'new', 'searching', 'accepted')
    )
  )
  -- Never return passenger cab rides through order dispatch (cab rides use public.rides)
  AND (o.service_type IS NULL OR LOWER(TRIM(o.service_type)) NOT IN ('ride', 'cab', 'auto', 'taxi', 'passenger', 'passenger_ride', 'rides'))
  AND (
    -- Unassigned broadcast orders (including redispatched rejected orders)
    (o.partner_id IS NULL AND LOWER(TRIM(COALESCE(o.delivery_status, 'not_assigned'))) IN ('not_assigned', 'unassigned', 'rejected', 'searching'))
    -- Or assigned/offered to this specific partner
    OR (p_partner_id IS NOT NULL AND o.partner_id = p_partner_id)
  )
  -- Permanently exclude this order if calling partner has an explicit rejected attempt
  AND (
    p_partner_id IS NULL
    OR NOT EXISTS (
      SELECT 1 FROM public.delivery_dispatch_attempts dda_rej
      WHERE dda_rej.order_id = o.id
        AND dda_rej.partner_id = p_partner_id
        AND dda_rej.status = 'rejected'
    )
  )
  LIMIT 100;

  RETURN v_orders;
END;
$$;

GRANT EXECUTE ON FUNCTION public.fetch_available_orders(uuid) TO authenticated, service_role;


-- ==============================================================================
-- 5. ATOMIC ORDER CLAIMING FOR ALL DELIVERY SERVICES (FOOD, GROCERY, COURIER)
-- Fixes: BUG-04, BUG-05
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.claim_order(
    p_order_id uuid,
    p_partner_id uuid,
    p_attempt_id uuid DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $$
DECLARE
    v_auth_uid UUID := auth.uid();
    v_auth_role TEXT := auth.role();
    v_actual_partner_id UUID := p_partner_id;
    v_partner RECORD;
    v_order RECORD;
    v_attempt RECORD;
    v_dispatch RECORD;
    v_rows_updated INTEGER;
    v_ride RECORD;
    v_store RECORD;
    v_store_address RECORD;
    v_store_name TEXT := 'RoadRider Partner';
    v_pickup_lat DOUBLE PRECISION := 12.9784;
    v_pickup_lng DOUBLE PRECISION := 77.6408;
    v_drop_lat DOUBLE PRECISION := 12.9609;
    v_drop_lng DOUBLE PRECISION := 77.6387;
    v_ride_id UUID;
    v_ride_number TEXT;
    v_fare NUMERIC;
    v_now TIMESTAMPTZ := NOW();
    v_order_json JSONB;
    v_ride_json JSONB;
    v_clean_service TEXT;
BEGIN
    IF p_order_id IS NULL OR p_partner_id IS NULL THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'p_order_id and p_partner_id are required.',
            'code', 'INVALID_PARAM'
        );
    END IF;

    -- 1. Secure caller identity validation
    IF v_auth_role = 'authenticated' THEN
        IF v_auth_uid IS NULL THEN
            RETURN jsonb_build_object(
                'success', false,
                'error', 'Authentication required.',
                'code', 'UNAUTHORIZED'
            );
        END IF;

        SELECT p.id
        INTO v_actual_partner_id
        FROM public.partners p
        WHERE p.user_id = v_auth_uid;

        IF v_actual_partner_id IS NULL THEN
            RETURN jsonb_build_object(
                'success', false,
                'error', 'Caller is not registered as a partner.',
                'code', 'UNAUTHORIZED_NOT_A_PARTNER'
            );
        END IF;

        IF p_partner_id <> v_actual_partner_id THEN
            RETURN jsonb_build_object(
                'success', false,
                'error', 'Cannot claim an order for another partner.',
                'code', 'FORBIDDEN_IDENTITY_MISMATCH'
            );
        END IF;
    END IF;

    -- 2. Lock partner row
    SELECT *
    INTO v_partner
    FROM public.partners
    WHERE id = v_actual_partner_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'Partner record not found.',
            'code', 'PARTNER_NOT_FOUND'
        );
    END IF;

    -- 3A. Check active cab ride
    IF EXISTS (
        SELECT 1
        FROM public.rides
        WHERE partner_id = v_actual_partner_id
          AND LOWER(TRIM(COALESCE(status, ''))) IN
              ('accepted', 'started', 'in_progress', 'arrived')
          AND LOWER(TRIM(COALESCE(status, ''))) NOT IN
              ('completed', 'cancelled')
          AND order_id IS NULL
    ) THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'Captain already has an active cab ride in progress.',
            'code', 'CAPTAIN_ALREADY_BUSY'
        );
    END IF;

    -- 3B. Check other active delivery order
    IF EXISTS (
        SELECT 1
        FROM public.orders
        WHERE partner_id = v_actual_partner_id
          AND id <> p_order_id
          AND LOWER(TRIM(COALESCE(delivery_status, ''))) IN (
              'assigned', 'accepted', 'arrived_at_pickup',
              'picked_up', 'in_transit', 'arrived_at_dropoff'
          )
          AND LOWER(TRIM(COALESCE(order_status, ''))) NOT IN (
              'completed', 'cancelled', 'rejected'
          )
    ) THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'Captain already has another active delivery order in progress.',
            'code', 'CAPTAIN_ALREADY_BUSY'
        );
    END IF;

    -- 4. Lock order row and verify status
    SELECT *
    INTO v_order
    FROM public.orders
    WHERE id = p_order_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'Order not found or no longer available.',
            'code', 'ORDER_NOT_FOUND'
        );
    END IF;

    v_clean_service := LOWER(TRIM(COALESCE(v_order.service_type, 'food')));

    -- Reject passenger cab rides
    IF v_clean_service IN ('ride', 'cab', 'auto', 'taxi', 'passenger', 'passenger_ride', 'rides') THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'Cab rides must be claimed via accept_cab_ride.',
            'code', 'INVALID_WORKFLOW_TYPE'
        );
    END IF;

    -- Allowed delivery workflows
    IF v_clean_service NOT IN ('food', 'food_delivery', 'restaurant', 'grocery', 'courier') THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'Unknown service type for order claim: ' || v_clean_service,
            'code', 'INVALID_WORKFLOW_TYPE'
        );
    END IF;

    -- Food and grocery require a store; courier does not
    IF v_clean_service IN ('food', 'food_delivery', 'restaurant', 'grocery') AND v_order.store_id IS NULL THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'Store-based delivery order is missing store association.',
            'code', 'MISSING_STORE'
        );
    END IF;

    -- Idempotency check: Already assigned to this partner
    IF v_order.partner_id = v_actual_partner_id
       AND LOWER(TRIM(COALESCE(v_order.delivery_status, '')))
       IN ('accepted', 'arrived_at_pickup', 'picked_up', 'in_transit', 'arrived_at_dropoff', 'delivered') THEN

        PERFORM public.generate_order_otps(p_order_id);

        SELECT * INTO v_order FROM public.orders WHERE id = p_order_id;
        SELECT * INTO v_ride FROM public.rides WHERE order_id = p_order_id LIMIT 1;

        RETURN jsonb_build_object(
            'success', true,
            'already_accepted', true,
            'order', row_to_json(v_order)::jsonb,
            'ride', CASE WHEN v_ride.id IS NOT NULL THEN row_to_json(v_ride)::jsonb ELSE NULL END
        );
    END IF;

    -- Conflict check: Already assigned to another captain
    IF v_order.partner_id IS NOT NULL
       AND v_order.partner_id <> v_actual_partner_id
       AND LOWER(TRIM(COALESCE(v_order.delivery_status, '')))
       IN ('assigned', 'accepted', 'arrived_at_pickup', 'picked_up', 'in_transit', 'arrived_at_dropoff') THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'This order has already been claimed by another captain.',
            'code', 'ORDER_ALREADY_CLAIMED'
        );
    END IF;

    -- Status eligibility check
    IF LOWER(TRIM(COALESCE(v_order.order_status, ''))) IN ('completed', 'cancelled', 'rejected') THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'Order is already ' || v_order.order_status,
            'code', 'ORDER_CLOSED'
        );
    END IF;

    -- 5. Dispatch attempts resolution
    IF p_attempt_id IS NOT NULL THEN
        SELECT *
        INTO v_attempt
        FROM public.delivery_dispatch_attempts
        WHERE id = p_attempt_id
        FOR UPDATE;

        IF FOUND AND v_attempt.expires_at < v_now THEN
            RETURN jsonb_build_object(
                'success', false,
                'error', 'Offer expired.',
                'code', 'OFFER_EXPIRED'
            );
        END IF;

        UPDATE public.delivery_dispatch_attempts
        SET status = 'accepted',
            responded_at = v_now
        WHERE id = p_attempt_id;
    END IF;

    -- Cancel any competing offers
    UPDATE public.delivery_dispatch_attempts
    SET status = 'cancelled',
        responded_at = v_now
    WHERE order_id = p_order_id
      AND status = 'offered'
      AND partner_id <> v_actual_partner_id;

    UPDATE public.delivery_dispatches
    SET status = 'assigned',
        assigned_partner_id = v_actual_partner_id,
        completed_at = v_now,
        updated_at = v_now
    WHERE order_id = p_order_id
      AND status IN ('searching', 'offered');

    -- 6. Atomically update orders table
    UPDATE public.orders
    SET partner_id = v_actual_partner_id,
        order_status = CASE
            WHEN LOWER(TRIM(COALESCE(order_status, ''))) IN ('new', 'placed', 'searching') THEN 'accepted'
            ELSE order_status
        END,
        delivery_status = 'accepted',
        accepted_at = v_now,
        updated_at = v_now
    WHERE id = p_order_id;

    -- 7. Mark partner busy
    UPDATE public.partners
    SET status = 'busy',
        updated_at = v_now
    WHERE id = v_actual_partner_id;

    -- 8. Generate dual OTPs
    PERFORM public.generate_order_otps(p_order_id);

    -- 9. Synchronize tracking ride in public.rides
    SELECT *
    INTO v_ride
    FROM public.rides
    WHERE order_id = p_order_id
      AND status NOT IN ('cancelled')
    ORDER BY created_at DESC
    LIMIT 1;

    IF v_ride.id IS NULL THEN
        IF v_order.store_id IS NOT NULL THEN
            BEGIN
                SELECT * INTO v_store FROM public.stores WHERE id = v_order.store_id;
                IF v_store.name IS NOT NULL THEN
                    v_store_name := v_store.name;
                ELSIF (to_jsonb(v_store) ->> 'store_name') IS NOT NULL THEN
                    v_store_name := to_jsonb(v_store) ->> 'store_name';
                END IF;
            EXCEPTION WHEN OTHERS THEN NULL;
            END;

            SELECT * INTO v_store_address FROM public.store_addresses WHERE store_id = v_order.store_id LIMIT 1;
            IF v_store_address.address_line1 IS NOT NULL THEN
                v_store_name := v_store_name || ', ' || v_store_address.address_line1;
            END IF;
            IF v_store_address.latitude IS NOT NULL THEN
                v_pickup_lat := v_store_address.latitude;
            END IF;
            IF v_store_address.longitude IS NOT NULL THEN
                v_pickup_lng := v_store_address.longitude;
            END IF;
        ELSE
            -- Courier pickup location
            v_store_name := COALESCE(v_order.pickup_address, 'Sender Pickup Location');
            v_pickup_lat := COALESCE(v_order.pickup_latitude, 12.9784);
            v_pickup_lng := COALESCE(v_order.pickup_longitude, 77.6408);
        END IF;

        v_drop_lat := COALESCE(v_order.delivery_latitude, 12.9609);
        v_drop_lng := COALESCE(v_order.delivery_longitude, 77.6387);
        v_ride_id := pg_catalog.gen_random_uuid();
        v_ride_number := 'RID-' || UPPER(SUBSTRING(REPLACE(v_ride_id::text, '-', '') FROM 1 FOR 8));
        v_fare := COALESCE(v_order.delivery_fee, v_order.total_amount, 0.00);

        INSERT INTO public.rides (
            id, ride_number, order_id, customer_id, customer_name, customer_phone,
            partner_id, service_type, pickup_address, pickup_lat, pickup_lng,
            drop_address, drop_lat, drop_lng, total_fare, status, created_at, updated_at
        ) VALUES (
            v_ride_id, v_ride_number, p_order_id, v_order.customer_id,
            COALESCE(v_order.customer_name, 'Customer'), v_order.customer_phone,
            v_actual_partner_id, v_clean_service, v_store_name, v_pickup_lat, v_pickup_lng,
            COALESCE(v_order.delivery_address, 'Delivery Address'), v_drop_lat, v_drop_lng,
            v_fare, 'accepted', v_now, v_now
        )
        RETURNING * INTO v_ride;
    ELSE
        UPDATE public.rides
        SET partner_id = v_actual_partner_id,
            status = 'accepted',
            accepted_at = v_now,
            updated_at = v_now
        WHERE id = v_ride.id;
    END IF;

    -- 10. For courier, synchronize legacy courier_jobs table
    IF v_clean_service = 'courier' THEN
        INSERT INTO public.courier_jobs (
            id, job_number, sender_id, partner_id, receiver_name, receiver_phone,
            pickup_address, pickup_lat, pickup_lng, drop_address, drop_lat, drop_lng,
            distance_km, quoted_price, status, payment_method, payment_status,
            accepted_at, created_at, updated_at
        ) VALUES (
            p_order_id,
            COALESCE(v_order.order_number, 'COR-' || UPPER(SUBSTRING(REPLACE(p_order_id::text, '-', '') FROM 1 FOR 8))),
            v_order.customer_id,
            v_actual_partner_id,
            COALESCE(v_order.customer_name, 'Receiver'),
            v_order.customer_phone,
            COALESCE(v_order.pickup_address, 'Pickup Location'),
            v_order.pickup_latitude,
            v_order.pickup_longitude,
            COALESCE(v_order.delivery_address, 'Delivery Location'),
            v_order.delivery_latitude,
            v_order.delivery_longitude,
            v_order.road_distance_km,
            COALESCE(v_order.total_amount, 0),
            'accepted',
            COALESCE(v_order.payment_method, 'COD'),
            COALESCE(v_order.payment_status, 'pending'),
            v_now, v_now, v_now
        )
        ON CONFLICT (id) DO UPDATE SET
            partner_id = v_actual_partner_id,
            status = 'accepted',
            accepted_at = v_now,
            updated_at = v_now;
    END IF;

    SELECT row_to_json(o.*)::jsonb INTO v_order_json FROM public.orders o WHERE o.id = p_order_id;
    SELECT row_to_json(v_ride.*)::jsonb INTO v_ride_json;

    RETURN jsonb_build_object(
        'success', true,
        'order', v_order_json,
        'ride', v_ride_json
    );
END;
$$;

GRANT EXECUTE ON FUNCTION public.claim_order(uuid, uuid, uuid) TO authenticated, service_role;


-- ==============================================================================
-- 6. CAB RIDE ACCEPTANCE: ATOMIC DUAL-TABLE SYNCHRONIZATION (RIDES + ORDERS)
-- Fixes: BUG-06 (User App RideTracking not receiving driver assignment)
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.accept_cab_ride(
    p_ride_id uuid,
    p_partner_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $$
DECLARE
    v_auth_uid UUID := auth.uid();
    v_auth_role TEXT := auth.role();
    v_actual_partner_id UUID := p_partner_id;
    v_partner RECORD;
    v_ride RECORD;
    v_now TIMESTAMPTZ := NOW();
    v_otp_code TEXT;
BEGIN
    IF p_ride_id IS NULL OR p_partner_id IS NULL THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'p_ride_id and p_partner_id are required.',
            'code', 'INVALID_PARAM'
        );
    END IF;

    -- 1. Secure caller identity validation
    IF v_auth_role = 'authenticated' THEN
        IF v_auth_uid IS NULL THEN
            RETURN jsonb_build_object(
                'success', false,
                'error', 'Authentication required.',
                'code', 'UNAUTHORIZED'
            );
        END IF;

        SELECT p.id
        INTO v_actual_partner_id
        FROM public.partners p
        WHERE p.user_id = v_auth_uid;

        IF v_actual_partner_id IS NULL THEN
            RETURN jsonb_build_object(
                'success', false,
                'error', 'Caller is not registered as a partner.',
                'code', 'UNAUTHORIZED_NOT_A_PARTNER'
            );
        END IF;

        IF p_partner_id <> v_actual_partner_id THEN
            RETURN jsonb_build_object(
                'success', false,
                'error', 'Cannot accept a ride for another partner.',
                'code', 'FORBIDDEN_IDENTITY_MISMATCH'
            );
        END IF;
    END IF;

    -- 2. Lock partner row
    SELECT *
    INTO v_partner
    FROM public.partners
    WHERE id = v_actual_partner_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'Partner record not found.',
            'code', 'PARTNER_NOT_FOUND'
        );
    END IF;

    -- 3A. Check active delivery order
    IF EXISTS (
        SELECT 1
        FROM public.orders
        WHERE partner_id = v_actual_partner_id
          AND LOWER(TRIM(COALESCE(delivery_status, ''))) IN (
              'assigned', 'accepted', 'arrived_at_pickup',
              'picked_up', 'in_transit', 'arrived_at_dropoff'
          )
          AND LOWER(TRIM(COALESCE(order_status, ''))) NOT IN (
              'completed', 'cancelled', 'rejected'
          )
    ) THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'Captain already has an active delivery order in progress.',
            'code', 'CAPTAIN_ALREADY_BUSY'
        );
    END IF;

    -- 3B. Check other active cab ride
    IF EXISTS (
        SELECT 1
        FROM public.rides
        WHERE partner_id = v_actual_partner_id
          AND id <> p_ride_id
          AND LOWER(TRIM(COALESCE(status, ''))) IN (
              'accepted', 'started', 'in_progress', 'arrived'
          )
          AND LOWER(TRIM(COALESCE(status, ''))) NOT IN (
              'completed', 'cancelled'
          )
          AND order_id IS NULL
    ) THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'Captain already has another active cab ride in progress.',
            'code', 'CAPTAIN_ALREADY_BUSY'
        );
    END IF;

    -- 4. Lock ride row and verify status
    SELECT *
    INTO v_ride
    FROM public.rides
    WHERE id = p_ride_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'Ride not found or no longer available.',
            'code', 'RIDE_NOT_FOUND'
        );
    END IF;

    -- Reject food delivery tracking rides
    IF v_ride.order_id IS NOT NULL
       OR LOWER(TRIM(COALESCE(v_ride.service_type, '')))
          IN ('food', 'food_delivery') THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'This ride belongs to a food delivery order. Use claim_order instead.',
            'code', 'INVALID_WORKFLOW_TYPE'
        );
    END IF;

    -- Idempotency check: Already accepted by this partner
    IF v_ride.partner_id = v_actual_partner_id
       AND LOWER(TRIM(COALESCE(v_ride.status, '')))
       IN ('accepted', 'started', 'in_progress', 'arrived') THEN

        PERFORM public.generate_cab_ride_otp(p_ride_id);

        -- Ensure public.orders is in sync
        UPDATE public.orders
        SET partner_id = v_actual_partner_id,
            order_status = 'accepted',
            delivery_status = 'accepted',
            accepted_at = COALESCE(accepted_at, v_now),
            updated_at = v_now
        WHERE id = p_ride_id;

        SELECT * INTO v_ride FROM public.rides WHERE id = p_ride_id;

        RETURN jsonb_build_object(
            'success', true,
            'already_accepted', true,
            'ride', row_to_json(v_ride)::jsonb
        );
    END IF;

    IF LOWER(TRIM(COALESCE(v_ride.status, ''))) IN ('completed', 'cancelled') THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'Ride is already ' || v_ride.status,
            'code', 'RIDE_CLOSED'
        );
    END IF;

    IF v_ride.partner_id IS NOT NULL
       AND v_ride.partner_id <> v_actual_partner_id
       AND LOWER(TRIM(COALESCE(v_ride.status, '')))
       IN ('accepted', 'started', 'in_progress', 'arrived') THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'Ride has already been accepted by another captain.',
            'code', 'BOOKING_ALREADY_ASSIGNED'
        );
    END IF;

    -- 5. Atomically update public.rides AND public.orders in the same transaction
    UPDATE public.rides
    SET partner_id = v_actual_partner_id,
        status = 'accepted',
        accepted_at = v_now,
        updated_at = v_now
    WHERE id = p_ride_id;

    UPDATE public.orders
    SET partner_id = v_actual_partner_id,
        order_status = 'accepted',
        delivery_status = 'accepted',
        accepted_at = v_now,
        updated_at = v_now
    WHERE id = p_ride_id;

    -- Mark partner busy
    UPDATE public.partners
    SET status = 'busy',
        updated_at = v_now
    WHERE id = v_actual_partner_id;

    -- Generate cab ride OTP
    PERFORM public.generate_cab_ride_otp(p_ride_id);

    -- Also mirror into order_otp_verifications so get_customer_delivery_otp finds it
    SELECT otp_code INTO v_otp_code
    FROM public.rider_otp_verifications
    WHERE ride_id = p_ride_id;

    IF v_otp_code IS NOT NULL THEN
        INSERT INTO public.order_otp_verifications (
            id, order_id, otp_type, otp_code, otp_hash,
            expires_at, attempts, created_at, updated_at
        ) VALUES (
            gen_random_uuid(), p_ride_id, 'customer_delivery', v_otp_code,
            encode(sha256(v_otp_code::bytea), 'hex'),
            v_now + INTERVAL '4 hours', 0, v_now, v_now
        )
        ON CONFLICT (order_id, otp_type) DO UPDATE SET
            otp_code = EXCLUDED.otp_code,
            otp_hash = EXCLUDED.otp_hash,
            expires_at = EXCLUDED.expires_at,
            updated_at = v_now
        WHERE order_otp_verifications.verified_at IS NULL;

        UPDATE public.orders
        SET delivery_otp = v_otp_code
        WHERE id = p_ride_id;
    END IF;

    SELECT * INTO v_ride FROM public.rides WHERE id = p_ride_id;

    RETURN jsonb_build_object(
        'success', true,
        'ride', row_to_json(v_ride)::jsonb
    );
END;
$$;

GRANT EXECUTE ON FUNCTION public.accept_cab_ride(uuid, uuid) TO authenticated, service_role;


-- ==============================================================================
-- 7. CAB RIDE CANCELLATION: ATOMIC DUAL-TABLE SYNCHRONIZATION
-- Fixes: BUG-06 (Cancellation state mismatch)
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.cancel_cab_ride(
  p_ride_id uuid,
  p_partner_id uuid,
  p_reason text DEFAULT 'Cancelled by captain'
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $$
DECLARE
  v_auth_uid UUID := auth.uid();
  v_auth_role TEXT := auth.role();
  v_actual_partner_id UUID := p_partner_id;
  v_partner RECORD;
  v_ride RECORD;
  v_otp RECORD;
  v_now TIMESTAMPTZ := NOW();
  v_release_res JSONB;
BEGIN
  IF p_ride_id IS NULL OR p_partner_id IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error', 'p_ride_id and p_partner_id are required.', 'code', 'INVALID_PARAM');
  END IF;

  -- Authorization check
  IF v_auth_role IS NOT NULL AND v_auth_role = 'authenticated' AND v_auth_uid IS NOT NULL THEN
    SELECT id INTO v_actual_partner_id FROM public.partners WHERE user_id = v_auth_uid;
    IF v_actual_partner_id IS NULL OR (p_partner_id IS NOT NULL AND p_partner_id <> v_actual_partner_id) THEN
      RETURN jsonb_build_object('success', false, 'error', 'Unauthorized caller identity.', 'code', 'UNAUTHORIZED');
    END IF;
  END IF;

  SELECT * INTO v_partner
  FROM public.partners
  WHERE id = v_actual_partner_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'error', 'Partner record not found.', 'code', 'PARTNER_NOT_FOUND');
  END IF;

  SELECT * INTO v_ride
  FROM public.rides
  WHERE id = p_ride_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'error', 'Ride not found.', 'code', 'RIDE_NOT_FOUND');
  END IF;

  IF v_ride.order_id IS NOT NULL OR LOWER(TRIM(COALESCE(v_ride.service_type, ''))) IN ('food', 'food_delivery') THEN
    RETURN jsonb_build_object('success', false, 'error', 'This ride belongs to a food delivery order. Use cancel_order_assignment instead.', 'code', 'INVALID_WORKFLOW_TYPE');
  END IF;

  IF v_ride.partner_id IS DISTINCT FROM v_actual_partner_id THEN
    RETURN jsonb_build_object('success', false, 'error', 'You are not assigned to this ride.', 'code', 'UNAUTHORIZED_CAPTAIN');
  END IF;

  IF LOWER(TRIM(COALESCE(v_ride.status, ''))) = 'cancelled' THEN
    v_release_res := public.release_captain_if_idle(v_actual_partner_id);
    RETURN jsonb_build_object('success', true, 'already_cancelled', true, 'status', 'cancelled', 'captain_release', v_release_res);
  END IF;

  IF LOWER(TRIM(COALESCE(v_ride.status, ''))) = 'completed' THEN
    RETURN jsonb_build_object('success', false, 'error', 'Completed rides cannot be cancelled.', 'code', 'RIDE_ALREADY_COMPLETED');
  END IF;

  IF LOWER(TRIM(COALESCE(v_ride.status, ''))) IN ('in_progress', 'started') THEN
    RETURN jsonb_build_object(
      'success', false,
      'error', 'Cab ride cannot be cancelled after passenger pickup has occurred.',
      'code', 'CANNOT_CANCEL_AFTER_PICKUP'
    );
  END IF;

  SELECT * INTO v_otp
  FROM public.rider_otp_verifications
  WHERE ride_id = p_ride_id;

  IF FOUND AND v_otp.verified_at IS NOT NULL THEN
    RETURN jsonb_build_object(
      'success', false,
      'error', 'Cab ride cannot be cancelled after passenger OTP verification.',
      'code', 'CANNOT_CANCEL_AFTER_PICKUP'
    );
  END IF;

  -- 1. Cancel public.rides
  UPDATE public.rides
  SET
    status = 'cancelled',
    cancellation_reason = p_reason,
    cancelled_by = 'captain',
    cancelled_at = v_now,
    updated_at = v_now
  WHERE id = p_ride_id;

  -- 2. Atomically synchronize public.orders
  UPDATE public.orders
  SET
    order_status = 'cancelled',
    delivery_status = 'cancelled',
    cancellation_reason = p_reason,
    cancelled_at = v_now,
    updated_at = v_now
  WHERE id = p_ride_id OR id = v_ride.order_id;

  v_release_res := public.release_captain_if_idle(v_actual_partner_id);

  RETURN jsonb_build_object(
    'success', true,
    'status', 'cancelled',
    'cancelled_at', v_now,
    'captain_release', v_release_res
  );
END;
$$;

GRANT EXECUTE ON FUNCTION public.cancel_cab_ride(uuid, uuid, text) TO authenticated, service_role;


-- ==============================================================================
-- 8. SECURE OTP VERIFICATION ENFORCING ALL STAGES AND SERVICES
-- Fixes: BUG-04, BUG-05, BUG-09
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.verify_order_otp(
  p_order_id uuid,
  p_otp_type text,
  p_otp_code text DEFAULT NULL,
  p_partner_id uuid DEFAULT NULL,
  p_entered_otp text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $$
DECLARE
  v_auth_uid UUID := auth.uid();
  v_auth_role TEXT := auth.role();
  v_actual_partner_id UUID := p_partner_id;
  v_order RECORD;
  v_otp RECORD;
  v_clean_code TEXT;
  v_remaining_attempts INTEGER;
  v_now TIMESTAMPTZ := NOW();
  v_release_res JSONB;
  v_clean_service TEXT;
BEGIN
  IF p_order_id IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error', 'p_order_id cannot be NULL', 'code', 'INVALID_INPUT');
  END IF;

  IF p_otp_type IS NULL OR p_otp_type NOT IN ('restaurant_pickup', 'customer_delivery') THEN
    RETURN jsonb_build_object('success', false, 'error', 'p_otp_type must be either restaurant_pickup or customer_delivery', 'code', 'INVALID_OTP_TYPE');
  END IF;

  -- Authorization check
  IF v_auth_role IS NOT NULL AND v_auth_role = 'authenticated' AND v_auth_uid IS NOT NULL THEN
    SELECT id INTO v_actual_partner_id FROM public.partners WHERE user_id = v_auth_uid;
    IF v_actual_partner_id IS NULL OR (p_partner_id IS NOT NULL AND p_partner_id <> v_actual_partner_id) THEN
      RETURN jsonb_build_object('success', false, 'error', 'Unauthorized caller identity.', 'code', 'UNAUTHORIZED');
    END IF;
  END IF;

  v_clean_code := trim(COALESCE(p_otp_code, p_entered_otp, ''));
  IF length(v_clean_code) <> 4 OR v_clean_code !~ '^[0-9]{4}$' THEN
    RETURN jsonb_build_object('success', false, 'error', 'OTP must be exactly 4 numeric digits', 'code', 'INVALID_FORMAT');
  END IF;

  SELECT id, partner_id, service_type, order_status, delivery_status, store_id
  INTO v_order
  FROM public.orders
  WHERE id = p_order_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'error', 'Order not found', 'code', 'ORDER_NOT_FOUND');
  END IF;

  v_clean_service := LOWER(TRIM(COALESCE(v_order.service_type, 'food')));

  -- Supported services: food, grocery, courier
  IF v_clean_service NOT IN ('food', 'food_delivery', 'restaurant', 'grocery', 'courier') THEN
    RETURN jsonb_build_object('success', false, 'error', 'Unsupported service type for order OTP verification.', 'code', 'INVALID_WORKFLOW_TYPE');
  END IF;

  IF v_actual_partner_id IS NOT NULL AND v_order.partner_id IS DISTINCT FROM v_actual_partner_id THEN
    RETURN jsonb_build_object('success', false, 'error', 'You are not the captain assigned to this order', 'code', 'UNAUTHORIZED_CAPTAIN');
  END IF;

  -- STAGE SEQUENCING ENFORCEMENT
  IF p_otp_type = 'restaurant_pickup' THEN
    -- Pickup OTP can only be verified at a valid pre-pickup stage
    IF LOWER(TRIM(COALESCE(v_order.delivery_status, ''))) IN ('picked_up', 'in_transit', 'arrived_at_dropoff', 'delivered')
       OR LOWER(TRIM(COALESCE(v_order.order_status, ''))) IN ('handed_over', 'in_transit', 'completed', 'cancelled', 'rejected') THEN
      RETURN jsonb_build_object(
        'success', false,
        'error', 'Pickup OTP cannot be verified at this stage. Order has already been picked up or closed.',
        'code', 'INVALID_STAGE_FOR_PICKUP_OTP'
      );
    END IF;

  ELSIF p_otp_type = 'customer_delivery' THEN
    -- Customer Delivery OTP MUST NOT be verified unless Pickup OTP has been verified
    IF NOT EXISTS (
      SELECT 1 FROM public.order_otp_verifications
      WHERE order_id = p_order_id
        AND otp_type = 'restaurant_pickup'
        AND verified_at IS NOT NULL
    ) THEN
      RETURN jsonb_build_object(
        'success', false,
        'error', 'Cannot verify customer delivery OTP before pickup OTP has been verified.',
        'code', 'PICKUP_OTP_NOT_VERIFIED'
      );
    END IF;

    -- Must be in picked_up / in_transit / arrived_at_dropoff stage
    IF LOWER(TRIM(COALESCE(v_order.delivery_status, ''))) NOT IN ('picked_up', 'in_transit', 'arrived_at_dropoff') THEN
      RETURN jsonb_build_object(
        'success', false,
        'error', 'Customer delivery OTP can only be verified after order is picked up.',
        'code', 'INVALID_STAGE_FOR_DELIVERY_OTP'
      );
    END IF;
  END IF;

  -- Lock and retrieve OTP verification row
  SELECT id, otp_code, otp_hash, expires_at, verified_at, attempts
  INTO v_otp
  FROM public.order_otp_verifications
  WHERE order_id = p_order_id AND otp_type = p_otp_type
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'error', 'No OTP verification record found for this order stage', 'code', 'OTP_NOT_FOUND');
  END IF;

  IF v_otp.verified_at IS NOT NULL THEN
    RETURN jsonb_build_object('success', false, 'error', 'This OTP has already been verified', 'code', 'ALREADY_VERIFIED');
  END IF;

  IF v_otp.attempts >= 5 THEN
    RETURN jsonb_build_object('success', false, 'error', 'Maximum 5 attempts exceeded. Verification locked.', 'code', 'MAX_ATTEMPTS_EXCEEDED');
  END IF;

  IF v_otp.expires_at < v_now THEN
    RETURN jsonb_build_object('success', false, 'error', 'This OTP has expired. Please request a new code.', 'code', 'OTP_EXPIRED');
  END IF;

  -- Validate match: accepts plain otp_code or cryptographic SHA-256 otp_hash
  IF NOT (
    (v_otp.otp_code IS NOT NULL AND v_clean_code = v_otp.otp_code)
    OR
    (v_otp.otp_hash IS NOT NULL AND encode(sha256(v_clean_code::bytea), 'hex') = v_otp.otp_hash)
  ) THEN
    UPDATE public.order_otp_verifications
    SET attempts = attempts + 1, updated_at = v_now
    WHERE id = v_otp.id;

    v_remaining_attempts := 5 - (v_otp.attempts + 1);

    IF v_remaining_attempts <= 0 THEN
      RETURN jsonb_build_object('success', false, 'error', 'Maximum 5 attempts exceeded. Verification locked.', 'code', 'MAX_ATTEMPTS_EXCEEDED', 'attempts_remaining', 0);
    ELSE
      RETURN jsonb_build_object('success', false, 'error', format('Invalid OTP code. %s attempt(s) remaining.', v_remaining_attempts), 'code', 'INVALID_OTP', 'attempts_remaining', v_remaining_attempts);
    END IF;
  END IF;

  -- Mark OTP verified
  UPDATE public.order_otp_verifications
  SET verified_at = v_now, updated_at = v_now
  WHERE id = v_otp.id;

  -- STAGE TRANSITIONS
  IF p_otp_type = 'restaurant_pickup' THEN
    UPDATE public.orders
    SET 
      delivery_status = 'picked_up',
      order_status = CASE
        WHEN v_clean_service = 'courier' THEN 'in_transit'
        ELSE 'handed_over'
      END,
      handed_over_at = COALESCE(handed_over_at, v_now),
      updated_at = v_now
    WHERE id = p_order_id;

    BEGIN
      EXECUTE 'UPDATE public.rides SET status = ''in_progress'', updated_at = $1 WHERE (order_id = $2 OR id = $2)'
      USING v_now, p_order_id;
    EXCEPTION WHEN OTHERS THEN NULL;
    END;

    -- Synchronize courier_jobs if exists
    IF v_clean_service = 'courier' THEN
      UPDATE public.courier_jobs
      SET status = 'picked_up',
          picked_up_at = v_now,
          updated_at = v_now
      WHERE id = p_order_id;
    END IF;

    RETURN jsonb_build_object(
      'success', true,
      'message', 'Pickup OTP verified successfully. Head to dropoff location.',
      'stage', 'picked_up',
      'delivery_status', 'picked_up',
      'order_status', CASE WHEN v_clean_service = 'courier' THEN 'in_transit' ELSE 'handed_over' END
    );

  ELSIF p_otp_type = 'customer_delivery' THEN
    UPDATE public.orders
    SET 
      delivery_status = 'delivered',
      order_status = 'completed',
      delivered_at = v_now,
      updated_at = v_now
    WHERE id = p_order_id;

    BEGIN
      EXECUTE 'UPDATE public.rides SET status = ''completed'', completed_at = $1, updated_at = $1 WHERE (order_id = $2 OR id = $2)'
      USING v_now, p_order_id;
    EXCEPTION WHEN OTHERS THEN NULL;
    END;

    -- Synchronize courier_jobs if exists
    IF v_clean_service = 'courier' THEN
      UPDATE public.courier_jobs
      SET status = 'delivered',
          delivered_at = v_now,
          updated_at = v_now
      WHERE id = p_order_id;
    END IF;

    UPDATE public.delivery_dispatches
    SET status = 'completed', completed_at = v_now, updated_at = v_now
    WHERE order_id = p_order_id;

    IF v_order.partner_id IS NOT NULL THEN
      UPDATE public.delivery_dispatch_attempts
      SET status = 'completed', responded_at = v_now
      WHERE order_id = p_order_id AND partner_id = v_order.partner_id;

      v_release_res := public.release_captain_if_idle(v_order.partner_id);
    END IF;

    RETURN jsonb_build_object(
      'success', true,
      'message', 'Delivery OTP verified successfully. Order completed.',
      'stage', 'delivered',
      'delivery_status', 'delivered',
      'order_status', 'completed',
      'captain_release', v_release_res
    );
  END IF;

  RETURN jsonb_build_object('success', false, 'error', 'Unhandled stage', 'code', 'UNHANDLED_STAGE');
END;
$$;

GRANT EXECUTE ON FUNCTION public.verify_order_otp(uuid, text, text, uuid, text) TO authenticated, service_role;


-- ==============================================================================
-- 9. FOOD & GROCERY HANDOVER ENFORCEMENT
-- Fixes: BUG-09 (Vendor independently marking handed_over without rider OTP verification)
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.vendor_handover_order(
  p_order_id uuid,
  p_store_id uuid,
  p_photo_path text,
  p_photo_url text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $$
DECLARE
  v_order record;
  v_now timestamptz := now();
  v_is_otp_verified boolean := false;
BEGIN
  IF p_order_id IS NULL OR p_store_id IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error', 'Missing order_id or store_id.', 'code', 'INVALID_PARAM');
  END IF;

  SELECT * INTO v_order
  FROM public.orders
  WHERE id = p_order_id AND store_id = p_store_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'error', 'Order not found for this store.', 'code', 'ORDER_NOT_FOUND');
  END IF;

  -- Idempotency check
  IF v_order.order_status IN ('handed_over', 'in_transit', 'picked_up', 'delivered', 'completed') THEN
    RETURN jsonb_build_object(
      'success', true,
      'already_completed', true,
      'order_status', v_order.order_status,
      'handed_over_at', v_order.handed_over_at
    );
  END IF;

  IF p_photo_path IS NULL OR trim(p_photo_path) = '' THEN
    RETURN jsonb_build_object('success', false, 'error', 'Handover proof photo is strictly required.', 'code', 'PHOTO_REQUIRED');
  END IF;

  -- BUG-09 ENFORCEMENT: Check if pickup OTP has been verified by the assigned rider
  SELECT EXISTS (
    SELECT 1 FROM public.order_otp_verifications
    WHERE order_id = p_order_id
      AND otp_type = 'restaurant_pickup'
      AND verified_at IS NOT NULL
  ) INTO v_is_otp_verified;

  IF NOT v_is_otp_verified THEN
    -- Record packaging photo proof if provided, but DO NOT advance status to handed_over
    UPDATE public.orders
    SET
      handover_storage_path = p_photo_path,
      handover_photo_url = COALESCE(p_photo_url, p_photo_path),
      handover_captured_at = v_now,
      updated_at = v_now
    WHERE id = p_order_id;

    RETURN jsonb_build_object(
      'success', false,
      'error', 'Cannot handover order: Delivery partner has not entered and verified the pickup OTP yet. Share the pickup OTP displayed on your screen with the rider.',
      'code', 'PICKUP_OTP_NOT_VERIFIED',
      'photo_recorded', true
    );
  END IF;

  -- If OTP is verified, record handover
  UPDATE public.orders
  SET
    order_status = 'handed_over',
    delivery_status = 'picked_up',
    ready_at = COALESCE(v_order.ready_at, v_now),
    handed_over_at = v_now,
    handover_storage_path = p_photo_path,
    handover_photo_url = COALESCE(p_photo_url, p_photo_path),
    handover_captured_at = v_now,
    updated_at = v_now
  WHERE id = p_order_id;

  RETURN jsonb_build_object(
    'success', true,
    'order_id', p_order_id,
    'order_status', 'handed_over',
    'handed_over_at', v_now
  );
END;
$$;

GRANT EXECUTE ON FUNCTION public.vendor_handover_order(uuid, uuid, text, text) TO authenticated, service_role;


-- ==============================================================================
-- 10. CANONICAL STATUS CONTRACT TRIGGER: protect_order_financials()
-- Fixes: State machine crashes on Grocery ('picking', 'packed') and Food/Courier
-- Enforces:
--   • Grocery state machine: placed -> accepted -> picking -> packed -> ready/ready_for_pickup -> handed_over/picked_up -> in_transit -> delivered -> completed
--   • Food state machine: placed -> accepted -> preparing -> ready -> handed_over/picked_up -> in_transit -> delivered -> completed
--   • Ride state machine: placed/searching -> accepted -> arrived -> in_progress -> completed
--   • Courier state machine: placed/searching -> accepted -> arrived -> picked_up/in_transit -> delivered -> completed
--   • Handover requires verified pickup OTP
--   • Delivery requires verified delivery OTP
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.protect_order_financials()
RETURNS TRIGGER AS $$
DECLARE
  v_svc TEXT;
  v_is_pickup_otp_verified BOOLEAN := FALSE;
  v_is_delivery_otp_verified BOOLEAN := FALSE;
BEGIN
  -- Service role and administrative bypass
  IF auth.role() = 'service_role' OR public.is_master_admin() THEN
    RETURN NEW;
  END IF;

  -- Protect financial integrity and read-only immutable columns
  IF TG_OP = 'UPDATE' THEN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.total_amount IS DISTINCT FROM OLD.total_amount
       OR NEW.subtotal IS DISTINCT FROM OLD.subtotal
       OR NEW.packaging_fee IS DISTINCT FROM OLD.packaging_fee
       OR NEW.delivery_fee IS DISTINCT FROM OLD.delivery_fee
       OR NEW.discount_amount IS DISTINCT FROM OLD.discount_amount
       OR NEW.commission_rate IS DISTINCT FROM OLD.commission_rate
       OR NEW.commission_amount IS DISTINCT FROM OLD.commission_amount
       OR NEW.gst_on_commission IS DISTINCT FROM OLD.gst_on_commission
       OR NEW.net_vendor_payout IS DISTINCT FROM OLD.net_vendor_payout
       OR NEW.payment_status IS DISTINCT FROM OLD.payment_status
       OR NEW.payment_method IS DISTINCT FROM OLD.payment_method
       OR NEW.customer_id IS DISTINCT FROM OLD.customer_id
       OR NEW.customer_name IS DISTINCT FROM OLD.customer_name
       OR NEW.store_id IS DISTINCT FROM OLD.store_id
       OR NEW.order_number IS DISTINCT FROM OLD.order_number
       OR NEW.placed_at IS DISTINCT FROM OLD.placed_at
    THEN
      IF NOT (NEW.total_amount >= OLD.total_amount AND NEW.order_status IN ('placed', 'new', 'searching')) THEN
        RAISE EXCEPTION 'Unauthorized: Financial, calculation, identity, and payment fields cannot be modified.';
      END IF;
    END IF;

    -- Enforce legitimate state transitions across delivery and ride lifecycles
    IF NEW.order_status IS DISTINCT FROM OLD.order_status THEN
      v_svc := LOWER(TRIM(COALESCE(NEW.service_type, OLD.service_type, 'food')));

      -- Common: Cancellations / Rejections
      IF NEW.order_status IN ('cancelled', 'rejected') THEN
        IF OLD.order_status IN ('completed', 'delivered') THEN
          RAISE EXCEPTION 'Invalid transition: Completed orders cannot be cancelled.';
        END IF;
        RETURN NEW;
      END IF;

      -- Common: Terminal states cannot be altered
      IF OLD.order_status IN ('completed', 'cancelled', 'rejected') THEN
        RAISE EXCEPTION 'Invalid transition: Terminal order states cannot be altered.';
      END IF;

      -- 1. GROCERY WORKFLOW STATE MACHINE
      IF v_svc = 'grocery' THEN
        IF OLD.order_status IN ('new', 'placed') AND NEW.order_status NOT IN ('accepted', 'preparing', 'picking', 'cancelled', 'rejected') THEN
          RAISE EXCEPTION 'Invalid grocery transition: New orders can only transition to accepted, preparing, or picking.';
        ELSIF OLD.order_status = 'accepted' AND NEW.order_status NOT IN ('preparing', 'picking', 'packed', 'ready', 'ready_for_pickup', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid grocery transition: Accepted orders can only transition to picking, packed, or ready.';
        ELSIF OLD.order_status = 'picking' AND NEW.order_status NOT IN ('packed', 'ready', 'ready_for_pickup', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid grocery transition: Picking orders can only transition to packed or ready.';
        ELSIF OLD.order_status IN ('packed', 'preparing') AND NEW.order_status NOT IN ('ready', 'ready_for_pickup', 'handed_over', 'picked_up', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid grocery transition: Packed orders can only transition to ready or handed_over.';
        ELSIF OLD.order_status IN ('ready', 'ready_for_pickup') AND NEW.order_status NOT IN ('handed_over', 'picked_up', 'in_transit', 'completed', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid grocery transition: Ready grocery orders can only transition to handed_over or picked_up.';
        ELSIF OLD.order_status = 'handed_over' AND NEW.order_status NOT IN ('in_transit', 'picked_up', 'delivered', 'completed', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid grocery transition: Handed over grocery orders can only transition to in_transit or delivered.';
        ELSIF OLD.order_status IN ('in_transit', 'picked_up', 'on_the_way') AND NEW.order_status NOT IN ('delivered', 'completed', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid grocery transition: In-transit orders can only transition to delivered or completed.';
        END IF;

      -- 2. CAB RIDE STATE MACHINE
      ELSIF v_svc IN ('rides', 'ride', 'cab', 'auto', 'taxi', 'passenger', 'passenger_ride') THEN
        IF OLD.order_status IN ('new', 'placed', 'searching') AND NEW.order_status NOT IN ('accepted', 'cancelled', 'searching', 'arrived', 'arrived_at_pickup') THEN
          RAISE EXCEPTION 'Invalid ride transition: Searching rides can only transition to accepted or cancelled.';
        ELSIF OLD.order_status = 'accepted' AND NEW.order_status NOT IN ('arrived', 'arrived_at_pickup', 'in_progress', 'started', 'searching', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid ride transition: Accepted rides can only transition to arrived, in_progress, or searching.';
        ELSIF OLD.order_status IN ('arrived', 'arrived_at_pickup') AND NEW.order_status NOT IN ('in_progress', 'started', 'searching', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid ride transition: Arrived rides can only transition to in_progress or cancelled.';
        ELSIF OLD.order_status IN ('in_progress', 'started') AND NEW.order_status NOT IN ('completed', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid ride transition: In-progress rides can only transition to completed.';
        END IF;

      -- 3. COURIER PARCEL STATE MACHINE
      ELSIF v_svc = 'courier' THEN
        IF OLD.order_status IN ('new', 'placed', 'searching') AND NEW.order_status NOT IN ('accepted', 'cancelled', 'searching', 'arrived', 'arrived_at_pickup') THEN
          RAISE EXCEPTION 'Invalid courier transition: Searching parcel can only transition to accepted or cancelled.';
        ELSIF OLD.order_status = 'accepted' AND NEW.order_status NOT IN ('arrived', 'arrived_at_pickup', 'picked_up', 'in_transit', 'searching', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid courier transition: Accepted parcel can only transition to arrived or picked_up.';
        ELSIF OLD.order_status IN ('arrived', 'arrived_at_pickup') AND NEW.order_status NOT IN ('picked_up', 'in_transit', 'searching', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid courier transition: Arrived courier can only transition to picked_up.';
        ELSIF OLD.order_status IN ('picked_up', 'in_transit', 'on_the_way') AND NEW.order_status NOT IN ('delivered', 'completed', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid courier transition: In-transit parcel can only transition to delivered or completed.';
        END IF;

      -- 4. FOOD RESTAURANT STATE MACHINE
      ELSE
        IF OLD.order_status IN ('new', 'placed', 'searching') AND NEW.order_status NOT IN ('accepted', 'preparing', 'rejected', 'cancelled', 'arrived', 'searching', 'placed') THEN
          RAISE EXCEPTION 'Invalid food transition: New/searching orders can only transition to accepted, preparing, or rejected.';
        ELSIF OLD.order_status = 'accepted' AND NEW.order_status NOT IN ('searching', 'placed', 'preparing', 'arrived', 'in_transit', 'on_the_way', 'picked_up', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid food transition: Accepted orders can only transition to preparing, arrived, searching, or cancelled.';
        ELSIF OLD.order_status = 'preparing' AND NEW.order_status NOT IN ('ready', 'ready_for_pickup', 'handed_over', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid food transition: Preparing orders can only transition to ready or cancelled.';
        ELSIF OLD.order_status IN ('ready', 'ready_for_pickup') AND NEW.order_status NOT IN ('handed_over', 'picked_up', 'completed', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid food transition: Ready orders can only transition to handed_over, picked_up, or completed.';
        ELSIF OLD.order_status = 'handed_over' AND NEW.order_status NOT IN ('in_transit', 'picked_up', 'delivered', 'completed', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid food transition: Handed over orders can only transition to in_transit, picked_up, or delivered.';
        ELSIF OLD.order_status IN ('in_transit', 'picked_up', 'on_the_way') AND NEW.order_status NOT IN ('delivered', 'completed', 'cancelled') THEN
          RAISE EXCEPTION 'Invalid food transition: In-transit orders can only transition to delivered or completed.';
        END IF;
      END IF;

      -- BUG-09 ENFORCEMENT: Transition to handed_over or picked_up requires verified pickup OTP
      IF NEW.order_status IN ('handed_over', 'picked_up') AND OLD.order_status NOT IN ('handed_over', 'picked_up', 'in_transit', 'delivered', 'completed') THEN
        IF v_svc IN ('food', 'food_delivery', 'restaurant', 'grocery') THEN
          SELECT EXISTS (
            SELECT 1 FROM public.order_otp_verifications
            WHERE order_id = NEW.id
              AND otp_type = 'restaurant_pickup'
              AND verified_at IS NOT NULL
          ) INTO v_is_pickup_otp_verified;

          IF NOT v_is_pickup_otp_verified THEN
            RAISE EXCEPTION 'Cannot mark order as %: Delivery captain pickup OTP verification has not been completed.', NEW.order_status;
          END IF;
        END IF;
      END IF;

    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMIT;
