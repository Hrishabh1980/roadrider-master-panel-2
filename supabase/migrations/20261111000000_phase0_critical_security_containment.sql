-- ==============================================================================
-- ROADRIDER PHASE 0: CRITICAL SECURITY & AUTHENTICATION CONTAINMENT
-- Migration: 20261111000000_phase0_critical_security_containment.sql
-- Date: 2026-11-11
--
-- TARGET BUGS FIXED:
--   BUG-01: Public & unauthorized direct access to order_otp_verifications
--   BUG-02: Public & anonymous access to orders and rides
--   BUG-03: Public exposure of driver real-time GPS, phone numbers & vehicles
-- ==============================================================================

-- ────────────────────────────────────────────────────────────────────────────
-- 1. REVOKE ANONYMOUS & PUBLIC PRIVILEGES ACROSS SENSITIVE TABLES
-- ────────────────────────────────────────────────────────────────────────────

-- Revoke all table-level privileges from anon on sensitive core tables
REVOKE ALL ON public.orders FROM anon;
REVOKE ALL ON public.rides FROM anon;
REVOKE ALL ON public.partners FROM anon;
REVOKE ALL ON public.vehicles FROM anon;
REVOKE ALL ON public.order_otp_verifications FROM anon;

-- Revoke direct write permissions on OTP tables from authenticated clients
-- (OTPs must strictly be generated and verified via SECURITY DEFINER functions)
REVOKE INSERT, UPDATE, DELETE ON public.order_otp_verifications FROM authenticated, anon, public;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'rider_otp_verifications') THEN
    EXECUTE 'REVOKE ALL ON public.rider_otp_verifications FROM anon';
    EXECUTE 'REVOKE INSERT, UPDATE, DELETE ON public.rider_otp_verifications FROM authenticated, anon, public';
  END IF;
END $$;

-- Revoke execute on internal OTP generation helpers from anon and public
REVOKE EXECUTE ON FUNCTION public.generate_secure_4digit_otp() FROM anon, public;
REVOKE EXECUTE ON FUNCTION public.generate_order_otps(uuid) FROM anon, public;
REVOKE EXECUTE ON FUNCTION public.verify_order_otp(uuid, text, text, uuid, text) FROM anon, public;
GRANT EXECUTE ON FUNCTION public.generate_order_otps(uuid) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.verify_order_otp(uuid, text, text, uuid, text) TO authenticated, service_role;

-- ────────────────────────────────────────────────────────────────────────────
-- 2. SECURE PUBLIC.PARTNERS: PREVENT CITY-WIDE DRIVER TRACKING & PII SCRAPING
-- ────────────────────────────────────────────────────────────────────────────
ALTER TABLE public.partners ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.partners FORCE ROW LEVEL SECURITY;

-- Drop all overly permissive or leaky policies on partners
DROP POLICY IF EXISTS "Public can view partner basic info" ON public.partners;
DROP POLICY IF EXISTS "Public can view online partner basic info" ON public.partners;
DROP POLICY IF EXISTS "Allow select for all" ON public.partners;
DROP POLICY IF EXISTS "Partners view all online" ON public.partners;
DROP POLICY IF EXISTS "Partners view own profile" ON public.partners;
DROP POLICY IF EXISTS "Partners can view own profile" ON public.partners;
DROP POLICY IF EXISTS "Users view assigned active partner" ON public.partners;
DROP POLICY IF EXISTS "Partners update own profile" ON public.partners;
DROP POLICY IF EXISTS "Partners can update own profile" ON public.partners;

-- Helper function: verify if a partner is assigned to an active order/ride of the current user
CREATE OR REPLACE FUNCTION public.is_assigned_partner_to_active_order(p_partner_id uuid, p_auth_uid uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.orders o
    WHERE o.partner_id = p_partner_id
      AND (
        o.customer_id = p_auth_uid
        OR o.customer_id = (SELECT id FROM public.customers WHERE auth_user_id = p_auth_uid LIMIT 1)
      )
      AND o.order_status IN ('accepted', 'preparing', 'food_ready', 'ready_for_pickup', 'picked_up', 'in_transit', 'assigned', 'on_way')
  )
  OR EXISTS (
    SELECT 1 FROM public.rides r
    WHERE r.partner_id = p_partner_id
      AND (
        r.customer_id = p_auth_uid
        OR r.customer_id = (SELECT id FROM public.customers WHERE auth_user_id = p_auth_uid LIMIT 1)
      )
      AND r.status IN ('accepted', 'arrived', 'in_progress', 'started')
  )
  OR EXISTS (
    SELECT 1 FROM public.orders o
    JOIN public.stores s ON s.id = o.store_id
    JOIN public.vendors v ON v.id = s.vendor_id
    WHERE o.partner_id = p_partner_id
      AND v.user_id = p_auth_uid
      AND o.order_status IN ('accepted', 'preparing', 'food_ready', 'ready_for_pickup', 'picked_up', 'in_transit', 'assigned')
  );
$$;

GRANT EXECUTE ON FUNCTION public.is_assigned_partner_to_active_order(uuid, uuid) TO authenticated;
REVOKE EXECUTE ON FUNCTION public.is_assigned_partner_to_active_order(uuid, uuid) FROM anon, public;

-- POLICY: Partners can view their own profile
CREATE POLICY "Partners view own profile" ON public.partners
  FOR SELECT TO authenticated
  USING (
    user_id = auth.uid()
    OR public.is_master_admin()
  );

-- POLICY: Customers and Vendors can only view the partner assigned to their active order
CREATE POLICY "Users view assigned active partner" ON public.partners
  FOR SELECT TO authenticated
  USING (
    public.is_assigned_partner_to_active_order(id, auth.uid())
  );

-- POLICY: Partners can update their own profile
CREATE POLICY "Partners update own profile" ON public.partners
  FOR UPDATE TO authenticated
  USING (
    user_id = auth.uid()
    OR public.is_master_admin()
  )
  WITH CHECK (
    user_id = auth.uid()
    OR public.is_master_admin()
  );

-- ────────────────────────────────────────────────────────────────────────────
-- 3. SECURE PUBLIC.VEHICLES: RESTRICT VEHICLE REGISTRATION DATA
-- ────────────────────────────────────────────────────────────────────────────
ALTER TABLE public.vehicles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vehicles FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Public can view vehicles" ON public.vehicles;
DROP POLICY IF EXISTS "Public view vehicles" ON public.vehicles;
DROP POLICY IF EXISTS "Partners and assigned users view vehicles" ON public.vehicles;

CREATE POLICY "Partners and assigned users view vehicles" ON public.vehicles
  FOR SELECT TO authenticated
  USING (
    partner_id = public.get_partner_id_by_auth(auth.uid())
    OR public.is_assigned_partner_to_active_order(partner_id, auth.uid())
    OR public.is_master_admin()
  );

-- ────────────────────────────────────────────────────────────────────────────
-- 4. SECURE PUBLIC.ORDERS: REMOVE BLANKET ACCESS & PREVENT ANONYMOUS LEAKS
-- ────────────────────────────────────────────────────────────────────────────
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.orders FORCE ROW LEVEL SECURITY;

-- Drop all overly permissive policies on orders
DROP POLICY IF EXISTS "Captains can view available and assigned orders" ON public.orders;
DROP POLICY IF EXISTS "Allow anon read orders" ON public.orders;
DROP POLICY IF EXISTS "Public orders read" ON public.orders;
DROP POLICY IF EXISTS "Public read orders" ON public.orders;
DROP POLICY IF EXISTS "Customers can view own orders" ON public.orders;
DROP POLICY IF EXISTS "Partners can view available and assigned orders" ON public.orders;
DROP POLICY IF EXISTS "Vendors can view own store orders" ON public.orders;

-- SELECT: Customers view own orders
CREATE POLICY "Customers can view own orders" ON public.orders
  FOR SELECT TO authenticated
  USING (
    customer_id = auth.uid()
    OR customer_id = public.get_customer_id_by_auth(auth.uid())
    OR public.is_master_admin()
  );

-- SELECT: Partners view assigned orders or eligible unassigned dispatch pool
CREATE POLICY "Partners can view available and assigned orders" ON public.orders
  FOR SELECT TO authenticated
  USING (
    partner_id = public.get_partner_id_by_auth(auth.uid())
    OR (
      partner_id IS NULL
      AND order_status IN ('placed', 'new', 'searching', 'accepted', 'ready', 'food_ready')
      AND public.is_online_approved_partner(auth.uid())
    )
    OR public.is_master_admin()
  );

-- SELECT: Vendors view orders for their own stores
CREATE POLICY "Vendors can view own store orders" ON public.orders
  FOR SELECT TO authenticated
  USING (
    public.is_vendor_store_owner(store_id)
    OR (vendor_id IS NOT NULL AND public.is_vendor_owner(vendor_id))
    OR public.is_master_admin()
  );

-- ────────────────────────────────────────────────────────────────────────────
-- 5. SECURE PUBLIC.RIDES: RESTRICT TO PASSENGER, DRIVER, ADMIN
-- ────────────────────────────────────────────────────────────────────────────
ALTER TABLE public.rides ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rides FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Captains can view available and assigned rides" ON public.rides;
DROP POLICY IF EXISTS "Riders can view own assigned rides" ON public.rides;
DROP POLICY IF EXISTS "Customers view own rides" ON public.rides;
DROP POLICY IF EXISTS "Customers insert rides" ON public.rides;
DROP POLICY IF EXISTS "Customers can view own rides" ON public.rides;
DROP POLICY IF EXISTS "Partners can view available and assigned rides" ON public.rides;

-- Customers view own rides
CREATE POLICY "Customers can view own rides" ON public.rides
  FOR SELECT TO authenticated
  USING (
    customer_id = auth.uid()
    OR customer_id = public.get_customer_id_by_auth(auth.uid())
    OR public.is_master_admin()
  );

-- Partners view assigned rides or unassigned searching rides
CREATE POLICY "Partners can view available and assigned rides" ON public.rides
  FOR SELECT TO authenticated
  USING (
    partner_id = public.get_partner_id_by_auth(auth.uid())
    OR (
      partner_id IS NULL
      AND status = 'searching'
      AND public.is_online_approved_partner(auth.uid())
    )
    OR public.is_master_admin()
  );

-- ────────────────────────────────────────────────────────────────────────────
-- 6. SECURE PUBLIC.ORDER_OTP_VERIFICATIONS & RIDER_OTP_VERIFICATIONS
-- ────────────────────────────────────────────────────────────────────────────
ALTER TABLE public.order_otp_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.order_otp_verifications FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Allow select order_otp_verifications" ON public.order_otp_verifications;
DROP POLICY IF EXISTS "Allow insert order_otp_verifications" ON public.order_otp_verifications;
DROP POLICY IF EXISTS "Allow update order_otp_verifications" ON public.order_otp_verifications;
DROP POLICY IF EXISTS "Captains can view assigned order otp status" ON public.order_otp_verifications;
DROP POLICY IF EXISTS "Customers can view assigned order otp status" ON public.order_otp_verifications;
DROP POLICY IF EXISTS "Customers view own order otp status" ON public.order_otp_verifications;
DROP POLICY IF EXISTS "Captains view assigned order otp status" ON public.order_otp_verifications;
DROP POLICY IF EXISTS "Vendors view store order otp status" ON public.order_otp_verifications;

-- Column SELECT grant strictly for safe metadata columns (otp_code excluded from direct table select)
GRANT SELECT (id, order_id, otp_type, expires_at, verified_at, attempts, created_at, updated_at)
  ON public.order_otp_verifications TO authenticated;

-- Customers can view verification metadata for their own order
CREATE POLICY "Customers view own order otp status" ON public.order_otp_verifications
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.orders o
      WHERE o.id = order_otp_verifications.order_id
        AND (
          o.customer_id = auth.uid()
          OR o.customer_id = public.get_customer_id_by_auth(auth.uid())
        )
    )
    OR public.is_master_admin()
  );

-- Assigned Captain can view verification metadata for assigned order
CREATE POLICY "Captains view assigned order otp status" ON public.order_otp_verifications
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.orders o
      WHERE o.id = order_otp_verifications.order_id
        AND o.partner_id = public.get_partner_id_by_auth(auth.uid())
    )
    OR public.is_master_admin()
  );

-- Store Vendor can view verification metadata for store order
CREATE POLICY "Vendors view store order otp status" ON public.order_otp_verifications
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.orders o
      WHERE o.id = order_otp_verifications.order_id
        AND (
          public.is_vendor_store_owner(o.store_id)
          OR (o.vendor_id IS NOT NULL AND public.is_vendor_owner(o.vendor_id))
        )
    )
    OR public.is_master_admin()
  );

-- Secure rider_otp_verifications if table exists
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'rider_otp_verifications') THEN
    ALTER TABLE public.rider_otp_verifications ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.rider_otp_verifications FORCE ROW LEVEL SECURITY;

    GRANT SELECT (id, ride_id, expires_at, verified_at, attempts, created_at, updated_at)
      ON public.rider_otp_verifications TO authenticated;

    DROP POLICY IF EXISTS "Passengers view ride otp status" ON public.rider_otp_verifications;
    CREATE POLICY "Passengers view ride otp status" ON public.rider_otp_verifications
      FOR SELECT TO authenticated
      USING (
        EXISTS (
          SELECT 1 FROM public.rides r
          WHERE r.id = rider_otp_verifications.ride_id
            AND (
              r.customer_id = auth.uid()
              OR r.customer_id = public.get_customer_id_by_auth(auth.uid())
            )
        )
        OR public.is_master_admin()
      );

    DROP POLICY IF EXISTS "Captains view ride otp status" ON public.rider_otp_verifications;
    CREATE POLICY "Captains view ride otp status" ON public.rider_otp_verifications
      FOR SELECT TO authenticated
      USING (
        EXISTS (
          SELECT 1 FROM public.rides r
          WHERE r.id = rider_otp_verifications.ride_id
            AND r.partner_id = public.get_partner_id_by_auth(auth.uid())
        )
        OR public.is_master_admin()
      );
  END IF;
END $$;
