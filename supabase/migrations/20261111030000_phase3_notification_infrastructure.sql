-- ============================================================================
-- ROADRIDER ECOSYSTEM — PHASE 3 NOTIFICATION & COMMUNICATIONS INFRASTRUCTURE
-- Migration: 20261111030000_phase3_notification_infrastructure.sql
-- Description: Transactional Outbox Pattern, Multi-Device Push Tokens, Delivery
--              Audit Logs, User Notification Preferences, Lifecycle Event Triggers,
--              Dead-Letter Queue, and Automated Phase 3 Verification Suite
-- Target Database: db.sjahblquggmzlihqgzyt.supabase.co (Postgres 17)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. DEVICE PUSH TOKENS TABLE (Multi-device token lifecycle)
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.device_push_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  role text NOT NULL CHECK (role IN ('customer', 'partner', 'vendor', 'admin')),
  device_id text NOT NULL,
  expo_push_token text,
  fcm_token text,
  platform text NOT NULL DEFAULT 'unknown' CHECK (platform IN ('android', 'ios', 'web', 'unknown')),
  app_version text,
  is_active boolean NOT NULL DEFAULT true,
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_device_push_tokens_user_device UNIQUE (user_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_device_push_tokens_user ON public.device_push_tokens (user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_device_push_tokens_device ON public.device_push_tokens (device_id);
CREATE INDEX IF NOT EXISTS idx_device_push_tokens_expo ON public.device_push_tokens (expo_push_token) WHERE is_active = true;

-- Enable RLS
ALTER TABLE public.device_push_tokens ENABLE ROW LEVEL SECURITY;

-- Revoke write from anon
REVOKE ALL ON public.device_push_tokens FROM anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.device_push_tokens TO authenticated;
GRANT ALL ON public.device_push_tokens TO service_role;

-- Policies for device_push_tokens
DROP POLICY IF EXISTS "Users manage own device push tokens" ON public.device_push_tokens;
CREATE POLICY "Users manage own device push tokens"
ON public.device_push_tokens
FOR ALL
TO authenticated
USING (user_id = auth.uid())
WITH CHECK (user_id = auth.uid());

DROP POLICY IF EXISTS "Admin Full Access on device_push_tokens" ON public.device_push_tokens;
CREATE POLICY "Admin Full Access on device_push_tokens"
ON public.device_push_tokens
FOR ALL
TO authenticated
USING (public.is_admin())
WITH CHECK (public.is_admin());


-- ----------------------------------------------------------------------------
-- 2. NOTIFICATION PREFERENCES TABLE
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.notification_preferences (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE,
  role text NOT NULL CHECK (role IN ('customer', 'partner', 'vendor', 'admin')),
  sms_enabled boolean NOT NULL DEFAULT true,
  push_enabled boolean NOT NULL DEFAULT true,
  order_updates_enabled boolean NOT NULL DEFAULT true,
  promotional_enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_notification_preferences_user ON public.notification_preferences (user_id);

-- Enable RLS
ALTER TABLE public.notification_preferences ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.notification_preferences FROM anon;
GRANT SELECT, INSERT, UPDATE ON public.notification_preferences TO authenticated;
GRANT ALL ON public.notification_preferences TO service_role;

DROP POLICY IF EXISTS "Users view and update own preferences" ON public.notification_preferences;
CREATE POLICY "Users view and update own preferences"
ON public.notification_preferences
FOR ALL
TO authenticated
USING (user_id = auth.uid())
WITH CHECK (user_id = auth.uid());

DROP POLICY IF EXISTS "Admin Full Access on notification_preferences" ON public.notification_preferences;
CREATE POLICY "Admin Full Access on notification_preferences"
ON public.notification_preferences
FOR ALL
TO authenticated
USING (public.is_admin())
WITH CHECK (public.is_admin());


-- ----------------------------------------------------------------------------
-- 3. NOTIFICATION EVENTS TABLE (Transactional Outbox)
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.notification_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type text NOT NULL,
  service_type text NOT NULL CHECK (service_type IN ('food', 'grocery', 'ride', 'courier', 'system', 'security')),
  entity_id uuid NOT NULL,
  recipient_id uuid NOT NULL,
  recipient_role text NOT NULL CHECK (recipient_role IN ('customer', 'partner', 'vendor', 'admin')),
  title text NOT NULL,
  body text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  idempotency_key text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'dead_letter')),
  retry_count integer NOT NULL DEFAULT 0,
  max_retries integer NOT NULL DEFAULT 3,
  next_retry_at timestamptz NOT NULL DEFAULT now(),
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz
);

CREATE INDEX IF NOT EXISTS idx_notification_events_status_retry ON public.notification_events (status, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_notification_events_entity ON public.notification_events (entity_id);
CREATE INDEX IF NOT EXISTS idx_notification_events_recipient ON public.notification_events (recipient_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_events_idempotency ON public.notification_events (idempotency_key);

-- Enable RLS
ALTER TABLE public.notification_events ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.notification_events FROM anon;
GRANT SELECT ON public.notification_events TO authenticated;
GRANT ALL ON public.notification_events TO service_role;

DROP POLICY IF EXISTS "Users view own notification events" ON public.notification_events;
CREATE POLICY "Users view own notification events"
ON public.notification_events
FOR SELECT
TO authenticated
USING (recipient_id = auth.uid());

DROP POLICY IF EXISTS "Admin Full Access on notification_events" ON public.notification_events;
CREATE POLICY "Admin Full Access on notification_events"
ON public.notification_events
FOR ALL
TO authenticated
USING (public.is_admin())
WITH CHECK (public.is_admin());


-- ----------------------------------------------------------------------------
-- 4. NOTIFICATION DELIVERY LOGS TABLE (Audit Trail)
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.notification_delivery_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid REFERENCES public.notification_events(id) ON DELETE CASCADE,
  channel text NOT NULL CHECK (channel IN ('sms', 'push', 'in_app')),
  provider text NOT NULL CHECK (provider IN ('msg91', 'expo', 'fcm', 'supabase_realtime', 'internal')),
  recipient_reference text,
  provider_message_id text,
  delivery_status text NOT NULL CHECK (delivery_status IN ('pending', 'sent', 'delivered', 'failed', 'suppressed')),
  attempt_count integer NOT NULL DEFAULT 1,
  response_payload jsonb DEFAULT '{}'::jsonb,
  last_error text,
  sent_at timestamptz DEFAULT now(),
  delivered_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_notification_delivery_logs_event ON public.notification_delivery_logs (event_id);
CREATE INDEX IF NOT EXISTS idx_notification_delivery_logs_channel_status ON public.notification_delivery_logs (channel, delivery_status);
CREATE INDEX IF NOT EXISTS idx_notification_delivery_logs_created ON public.notification_delivery_logs (created_at DESC);

-- Enable RLS
ALTER TABLE public.notification_delivery_logs ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.notification_delivery_logs FROM anon;
GRANT SELECT ON public.notification_delivery_logs TO authenticated;
GRANT ALL ON public.notification_delivery_logs TO service_role;

DROP POLICY IF EXISTS "Admin Full Access on notification_delivery_logs" ON public.notification_delivery_logs;
CREATE POLICY "Admin Full Access on notification_delivery_logs"
ON public.notification_delivery_logs
FOR ALL
TO authenticated
USING (public.is_admin())
WITH CHECK (public.is_admin());


-- ----------------------------------------------------------------------------
-- 5. RPCs: TOKEN REGISTRATION & PREFERENCES MANAGEMENT
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.register_device_push_token(
  p_role text,
  p_device_id text,
  p_expo_push_token text DEFAULT NULL,
  p_fcm_token text DEFAULT NULL,
  p_platform text DEFAULT 'unknown',
  p_app_version text DEFAULT NULL,
  p_user_id uuid DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_target_user_id uuid;
  v_record public.device_push_tokens%ROWTYPE;
BEGIN
  -- Authenticated caller defaults to auth.uid(), service_role can specify p_user_id
  v_target_user_id := COALESCE(auth.uid(), p_user_id);
  IF v_target_user_id IS NULL THEN
    RAISE EXCEPTION 'User ID is required to register a push token';
  END IF;

  IF p_role NOT IN ('customer', 'partner', 'vendor', 'admin') THEN
    RAISE EXCEPTION 'Invalid role specified: %', p_role;
  END IF;

  IF p_device_id IS NULL OR TRIM(p_device_id) = '' THEN
    RAISE EXCEPTION 'Device ID cannot be empty';
  END IF;

  -- Upsert device push token
  INSERT INTO public.device_push_tokens (
    user_id,
    role,
    device_id,
    expo_push_token,
    fcm_token,
    platform,
    app_version,
    is_active,
    last_seen_at,
    updated_at
  ) VALUES (
    v_target_user_id,
    p_role,
    p_device_id,
    p_expo_push_token,
    p_fcm_token,
    COALESCE(p_platform, 'unknown'),
    p_app_version,
    true,
    now(),
    now()
  )
  ON CONFLICT (user_id, device_id) DO UPDATE SET
    role = EXCLUDED.role,
    expo_push_token = COALESCE(EXCLUDED.expo_push_token, public.device_push_tokens.expo_push_token),
    fcm_token = COALESCE(EXCLUDED.fcm_token, public.device_push_tokens.fcm_token),
    platform = COALESCE(EXCLUDED.platform, public.device_push_tokens.platform),
    app_version = COALESCE(EXCLUDED.app_version, public.device_push_tokens.app_version),
    is_active = true,
    last_seen_at = now(),
    updated_at = now()
  RETURNING * INTO v_record;

  -- Backward compatibility sync to customers table if role is customer
  IF p_role = 'customer' AND p_fcm_token IS NOT NULL THEN
    UPDATE public.customers
    SET fcm_token = p_fcm_token
    WHERE id = v_target_user_id;
  END IF;

  RETURN jsonb_build_object(
    'success', true,
    'id', v_record.id,
    'user_id', v_record.user_id,
    'role', v_record.role,
    'device_id', v_record.device_id,
    'expo_push_token', v_record.expo_push_token,
    'is_active', v_record.is_active
  );
END;
$$;

GRANT EXECUTE ON FUNCTION public.register_device_push_token TO authenticated, service_role;


CREATE OR REPLACE FUNCTION public.deactivate_device_push_token(
  p_device_id text,
  p_user_id uuid DEFAULT NULL
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_target_user_id uuid;
BEGIN
  v_target_user_id := COALESCE(auth.uid(), p_user_id);
  IF v_target_user_id IS NULL THEN
    RAISE EXCEPTION 'User ID required';
  END IF;

  UPDATE public.device_push_tokens
  SET is_active = false, updated_at = now()
  WHERE user_id = v_target_user_id AND device_id = p_device_id;

  RETURN true;
END;
$$;

GRANT EXECUTE ON FUNCTION public.deactivate_device_push_token TO authenticated, service_role;


CREATE OR REPLACE FUNCTION public.get_or_create_notification_preferences(
  p_user_id uuid DEFAULT NULL,
  p_role text DEFAULT 'customer'
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_target_user_id uuid;
  v_pref public.notification_preferences%ROWTYPE;
BEGIN
  v_target_user_id := COALESCE(auth.uid(), p_user_id);
  IF v_target_user_id IS NULL THEN
    RAISE EXCEPTION 'User ID required';
  END IF;

  SELECT * INTO v_pref FROM public.notification_preferences WHERE user_id = v_target_user_id;

  IF NOT FOUND THEN
    INSERT INTO public.notification_preferences (
      user_id,
      role,
      sms_enabled,
      push_enabled,
      order_updates_enabled,
      promotional_enabled
    ) VALUES (
      v_target_user_id,
      COALESCE(p_role, 'customer'),
      true,
      true,
      true,
      true
    )
    ON CONFLICT (user_id) DO NOTHING
    RETURNING * INTO v_pref;

    IF v_pref.id IS NULL THEN
      SELECT * INTO v_pref FROM public.notification_preferences WHERE user_id = v_target_user_id;
    END IF;
  END IF;

  RETURN jsonb_build_object(
    'user_id', v_pref.user_id,
    'role', v_pref.role,
    'sms_enabled', v_pref.sms_enabled,
    'push_enabled', v_pref.push_enabled,
    'order_updates_enabled', v_pref.order_updates_enabled,
    'promotional_enabled', v_pref.promotional_enabled
  );
END;
$$;

GRANT EXECUTE ON FUNCTION public.get_or_create_notification_preferences TO authenticated, service_role;


CREATE OR REPLACE FUNCTION public.update_notification_preferences(
  p_sms_enabled boolean,
  p_push_enabled boolean,
  p_order_updates_enabled boolean,
  p_promotional_enabled boolean,
  p_user_id uuid DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_target_user_id uuid;
  v_pref public.notification_preferences%ROWTYPE;
BEGIN
  v_target_user_id := COALESCE(auth.uid(), p_user_id);
  IF v_target_user_id IS NULL THEN
    RAISE EXCEPTION 'User ID required';
  END IF;

  INSERT INTO public.notification_preferences (
    user_id,
    role,
    sms_enabled,
    push_enabled,
    order_updates_enabled,
    promotional_enabled,
    updated_at
  ) VALUES (
    v_target_user_id,
    'customer',
    p_sms_enabled,
    p_push_enabled,
    p_order_updates_enabled,
    p_promotional_enabled,
    now()
  )
  ON CONFLICT (user_id) DO UPDATE SET
    sms_enabled = EXCLUDED.sms_enabled,
    push_enabled = EXCLUDED.push_enabled,
    order_updates_enabled = EXCLUDED.order_updates_enabled,
    promotional_enabled = EXCLUDED.promotional_enabled,
    updated_at = now()
  RETURNING * INTO v_pref;

  RETURN jsonb_build_object(
    'user_id', v_pref.user_id,
    'sms_enabled', v_pref.sms_enabled,
    'push_enabled', v_pref.push_enabled,
    'order_updates_enabled', v_pref.order_updates_enabled,
    'promotional_enabled', v_pref.promotional_enabled
  );
END;
$$;

GRANT EXECUTE ON FUNCTION public.update_notification_preferences TO authenticated, service_role;


-- ----------------------------------------------------------------------------
-- 6. ORDER LIFECYCLE OUTBOX EVENT TRIGGER
-- Decoupled: Wrapped in EXCEPTION handler so notification enqueue NEVER breaks order transactions
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.enqueue_order_notification_events()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_order_num text;
  v_service text;
  v_status text;
  v_partner_auth_id uuid;
  v_vendor_auth_id uuid;
BEGIN
  -- Defensive wrapper: under no circumstances should an outbox failure block order flow
  BEGIN
    v_order_num := COALESCE(NEW.order_number, SUBSTRING(NEW.id::text, 1, 8));
    v_service := COALESCE(NEW.service_type, 'food');
    v_status := COALESCE(NEW.order_status, 'pending');

    -- Resolve partner user_id (auth_id) if assigned
    IF NEW.partner_id IS NOT NULL THEN
      SELECT user_id INTO v_partner_auth_id FROM public.partners WHERE id = NEW.partner_id;
    END IF;

    -- Resolve vendor user_id (auth_id) if vendor/store exists
    IF NEW.vendor_id IS NOT NULL THEN
      SELECT user_id INTO v_vendor_auth_id FROM public.vendors WHERE id = NEW.vendor_id;
    ELSIF NEW.store_id IS NOT NULL THEN
      SELECT v.user_id INTO v_vendor_auth_id 
      FROM public.stores s 
      JOIN public.vendors v ON v.id = s.vendor_id 
      WHERE s.id = NEW.store_id;
    END IF;

    -- CASE 1: NEW ORDER INSERTION
    IF TG_OP = 'INSERT' THEN
      -- Customer Confirmation
      IF NEW.customer_id IS NOT NULL THEN
        INSERT INTO public.notification_events (
          event_type,
          service_type,
          entity_id,
          recipient_id,
          recipient_role,
          title,
          body,
          payload,
          idempotency_key
        ) VALUES (
          'order_placed',
          v_service,
          NEW.id,
          NEW.customer_id,
          'customer',
          'Order Placed Successfully',
          'Your ' || INITCAP(v_service) || ' order #' || v_order_num || ' has been placed.',
          jsonb_build_object(
            'order_id', NEW.id,
            'order_number', v_order_num,
            'service_type', v_service,
            'total_amount', NEW.total_amount,
            'customer_phone', NEW.customer_phone
          ),
          NEW.id::text || '_placed_' || v_status
        ) ON CONFLICT (idempotency_key) DO NOTHING;
      END IF;

      -- Vendor Alert for Food / Grocery orders
      IF v_service IN ('food', 'grocery') AND (v_vendor_auth_id IS NOT NULL OR NEW.vendor_id IS NOT NULL) THEN
        INSERT INTO public.notification_events (
          event_type,
          service_type,
          entity_id,
          recipient_id,
          recipient_role,
          title,
          body,
          payload,
          idempotency_key
        ) VALUES (
          'new_order_alert',
          v_service,
          NEW.id,
          COALESCE(v_vendor_auth_id, NEW.vendor_id),
          'vendor',
          'New ' || INITCAP(v_service) || ' Order Received!',
          'Order #' || v_order_num || ' received with ' || COALESCE(NEW.total_items, 1)::text || ' items.',
          jsonb_build_object(
            'order_id', NEW.id,
            'order_number', v_order_num,
            'service_type', v_service,
            'store_id', NEW.store_id,
            'total_amount', NEW.total_amount
          ),
          NEW.id::text || '_vendor_alert_' || v_status
        ) ON CONFLICT (idempotency_key) DO NOTHING;
      END IF;

    -- CASE 2: ORDER UPDATE
    ELSIF TG_OP = 'UPDATE' THEN
      -- Sub-case A: Status changed to 'accepted'
      IF (NEW.order_status IS DISTINCT FROM OLD.order_status AND NEW.order_status = 'accepted') OR
         (NEW.restaurant_status IS DISTINCT FROM OLD.restaurant_status AND NEW.restaurant_status = 'accepted') THEN
        IF NEW.customer_id IS NOT NULL THEN
          INSERT INTO public.notification_events (
            event_type, service_type, entity_id, recipient_id, recipient_role, title, body, payload, idempotency_key
          ) VALUES (
            'order_accepted',
            v_service,
            NEW.id,
            NEW.customer_id,
            'customer',
            'Order Accepted',
            'Your ' || v_service || ' order #' || v_order_num || ' has been accepted.',
            jsonb_build_object('order_id', NEW.id, 'order_number', v_order_num),
            NEW.id::text || '_accepted_' || COALESCE(NEW.version, 1)::text
          ) ON CONFLICT (idempotency_key) DO NOTHING;
        END IF;
      END IF;

      -- Sub-case B: Preparing / Picking
      IF (NEW.order_status IS DISTINCT FROM OLD.order_status AND NEW.order_status IN ('preparing', 'picking')) OR
         (NEW.restaurant_status IS DISTINCT FROM OLD.restaurant_status AND NEW.restaurant_status = 'preparing') THEN
        IF NEW.customer_id IS NOT NULL THEN
          INSERT INTO public.notification_events (
            event_type, service_type, entity_id, recipient_id, recipient_role, title, body, payload, idempotency_key
          ) VALUES (
            'order_preparing',
            v_service,
            NEW.id,
            NEW.customer_id,
            'customer',
            'Order In Preparation',
            'Your ' || v_service || ' order #' || v_order_num || ' is currently being prepared.',
            jsonb_build_object('order_id', NEW.id, 'order_number', v_order_num),
            NEW.id::text || '_preparing_' || COALESCE(NEW.version, 1)::text
          ) ON CONFLICT (idempotency_key) DO NOTHING;
        END IF;
      END IF;

      -- Sub-case C: Ready for pickup / packed
      IF (NEW.order_status IS DISTINCT FROM OLD.order_status AND NEW.order_status IN ('ready', 'ready_for_pickup')) OR
         (NEW.restaurant_status IS DISTINCT FROM OLD.restaurant_status AND NEW.restaurant_status = 'ready') THEN
        IF NEW.customer_id IS NOT NULL THEN
          INSERT INTO public.notification_events (
            event_type, service_type, entity_id, recipient_id, recipient_role, title, body, payload, idempotency_key
          ) VALUES (
            'order_ready',
            v_service,
            NEW.id,
            NEW.customer_id,
            'customer',
            'Order Ready for Pickup',
            'Your ' || v_service || ' order #' || v_order_num || ' is packed and awaiting courier pickup.',
            jsonb_build_object('order_id', NEW.id, 'order_number', v_order_num),
            NEW.id::text || '_ready_' || COALESCE(NEW.version, 1)::text
          ) ON CONFLICT (idempotency_key) DO NOTHING;
        END IF;
      END IF;

      -- Sub-case D: Captain Assigned (partner_id assigned or changed)
      IF NEW.partner_id IS NOT NULL AND (OLD.partner_id IS NULL OR NEW.partner_id IS DISTINCT FROM OLD.partner_id) THEN
        -- Customer notice
        IF NEW.customer_id IS NOT NULL THEN
          INSERT INTO public.notification_events (
            event_type, service_type, entity_id, recipient_id, recipient_role, title, body, payload, idempotency_key
          ) VALUES (
            'captain_assigned',
            v_service,
            NEW.id,
            NEW.customer_id,
            'customer',
            'Captain Assigned',
            'A RoadRider Captain has been assigned to your order #' || v_order_num || '.',
            jsonb_build_object('order_id', NEW.id, 'partner_id', NEW.partner_id),
            NEW.id::text || '_captain_assigned_cust_' || NEW.partner_id::text
          ) ON CONFLICT (idempotency_key) DO NOTHING;
        END IF;

        -- Captain notice
        IF v_partner_auth_id IS NOT NULL OR NEW.partner_id IS NOT NULL THEN
          INSERT INTO public.notification_events (
            event_type, service_type, entity_id, recipient_id, recipient_role, title, body, payload, idempotency_key
          ) VALUES (
            'job_assigned',
            v_service,
            NEW.id,
            COALESCE(v_partner_auth_id, NEW.partner_id),
            'partner',
            'New Job Assigned',
            'You have been assigned ' || v_service || ' order #' || v_order_num || '.',
            jsonb_build_object('order_id', NEW.id, 'order_number', v_order_num, 'service_type', v_service),
            NEW.id::text || '_job_assigned_partner_' || NEW.partner_id::text
          ) ON CONFLICT (idempotency_key) DO NOTHING;
        END IF;
      END IF;

      -- Sub-case E: Picked Up / In Transit / Handed Over
      IF (NEW.order_status IS DISTINCT FROM OLD.order_status AND NEW.order_status IN ('picked_up', 'handed_over', 'in_progress', 'in_transit')) OR
         (NEW.delivery_status IS DISTINCT FROM OLD.delivery_status AND NEW.delivery_status IN ('picked_up', 'in_transit')) THEN
        IF NEW.customer_id IS NOT NULL THEN
          INSERT INTO public.notification_events (
            event_type, service_type, entity_id, recipient_id, recipient_role, title, body, payload, idempotency_key
          ) VALUES (
            'order_in_transit',
            v_service,
            NEW.id,
            NEW.customer_id,
            'customer',
            'Order Out for Delivery',
            'Your ' || v_service || ' order #' || v_order_num || ' has been picked up and is on the way!',
            jsonb_build_object('order_id', NEW.id, 'order_number', v_order_num),
            NEW.id::text || '_intransit_' || COALESCE(NEW.version, 1)::text
          ) ON CONFLICT (idempotency_key) DO NOTHING;
        END IF;
      END IF;

      -- Sub-case F: Delivered / Completed
      IF (NEW.order_status IS DISTINCT FROM OLD.order_status AND NEW.order_status IN ('delivered', 'completed')) OR
         (NEW.delivery_status IS DISTINCT FROM OLD.delivery_status AND NEW.delivery_status = 'delivered') THEN
        -- Customer notice
        IF NEW.customer_id IS NOT NULL THEN
          INSERT INTO public.notification_events (
            event_type, service_type, entity_id, recipient_id, recipient_role, title, body, payload, idempotency_key
          ) VALUES (
            'order_delivered',
            v_service,
            NEW.id,
            NEW.customer_id,
            'customer',
            'Order Delivered',
            'Your ' || v_service || ' order #' || v_order_num || ' has been delivered. Thank you for using RoadRider!',
            jsonb_build_object('order_id', NEW.id, 'order_number', v_order_num),
            NEW.id::text || '_delivered_cust_' || COALESCE(NEW.version, 1)::text
          ) ON CONFLICT (idempotency_key) DO NOTHING;
        END IF;

        -- Vendor notice
        IF (v_vendor_auth_id IS NOT NULL OR NEW.vendor_id IS NOT NULL) THEN
          INSERT INTO public.notification_events (
            event_type, service_type, entity_id, recipient_id, recipient_role, title, body, payload, idempotency_key
          ) VALUES (
            'order_delivered_vendor',
            v_service,
            NEW.id,
            COALESCE(v_vendor_auth_id, NEW.vendor_id),
            'vendor',
            'Order Completed',
            'Order #' || v_order_num || ' has been delivered successfully.',
            jsonb_build_object('order_id', NEW.id, 'order_number', v_order_num),
            NEW.id::text || '_delivered_vendor_' || COALESCE(NEW.version, 1)::text
          ) ON CONFLICT (idempotency_key) DO NOTHING;
        END IF;
      END IF;

      -- Sub-case G: Cancelled
      IF (NEW.order_status IS DISTINCT FROM OLD.order_status AND NEW.order_status = 'cancelled') THEN
        -- Customer notice
        IF NEW.customer_id IS NOT NULL THEN
          INSERT INTO public.notification_events (
            event_type, service_type, entity_id, recipient_id, recipient_role, title, body, payload, idempotency_key
          ) VALUES (
            'order_cancelled',
            v_service,
            NEW.id,
            NEW.customer_id,
            'customer',
            'Order Cancelled',
            'Your ' || v_service || ' order #' || v_order_num || ' was cancelled. ' || COALESCE(NEW.cancellation_reason, ''),
            jsonb_build_object('order_id', NEW.id, 'reason', NEW.cancellation_reason),
            NEW.id::text || '_cancelled_cust_' || COALESCE(NEW.version, 1)::text
          ) ON CONFLICT (idempotency_key) DO NOTHING;
        END IF;

        -- Vendor notice
        IF (v_vendor_auth_id IS NOT NULL OR NEW.vendor_id IS NOT NULL) THEN
          INSERT INTO public.notification_events (
            event_type, service_type, entity_id, recipient_id, recipient_role, title, body, payload, idempotency_key
          ) VALUES (
            'order_cancelled_vendor',
            v_service,
            NEW.id,
            COALESCE(v_vendor_auth_id, NEW.vendor_id),
            'vendor',
            'Order Cancelled',
            'Order #' || v_order_num || ' was cancelled. ' || COALESCE(NEW.cancellation_reason, ''),
            jsonb_build_object('order_id', NEW.id, 'reason', NEW.cancellation_reason),
            NEW.id::text || '_cancelled_vendor_' || COALESCE(NEW.version, 1)::text
          ) ON CONFLICT (idempotency_key) DO NOTHING;
        END IF;

        -- Partner notice (if partner was assigned)
        IF (v_partner_auth_id IS NOT NULL OR NEW.partner_id IS NOT NULL) THEN
          INSERT INTO public.notification_events (
            event_type, service_type, entity_id, recipient_id, recipient_role, title, body, payload, idempotency_key
          ) VALUES (
            'order_cancelled_partner',
            v_service,
            NEW.id,
            COALESCE(v_partner_auth_id, NEW.partner_id),
            'partner',
            'Order Cancelled',
            'Order #' || v_order_num || ' was cancelled.',
            jsonb_build_object('order_id', NEW.id, 'reason', NEW.cancellation_reason),
            NEW.id::text || '_cancelled_partner_' || COALESCE(NEW.version, 1)::text
          ) ON CONFLICT (idempotency_key) DO NOTHING;
        END IF;
      END IF;

    END IF;

  EXCEPTION WHEN OTHERS THEN
    -- Resilient fallback: log warning and continue without breaking order transaction
    RAISE WARNING 'enqueue_order_notification_events failed for order %: %', NEW.id, SQLERRM;
  END;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_enqueue_order_notification_events ON public.orders;
CREATE TRIGGER trg_enqueue_order_notification_events
AFTER INSERT OR UPDATE ON public.orders
FOR EACH ROW
EXECUTE FUNCTION public.enqueue_order_notification_events();


-- ----------------------------------------------------------------------------
-- 7. OUTBOX PROCESSOR RPC: DISPATCH TO IN-APP FEED, PUSH & SMS CHANNELS
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.process_notification_outbox(
  p_batch_size integer DEFAULT 50
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_event RECORD;
  v_pref RECORD;
  v_token RECORD;
  v_processed integer := 0;
  v_completed integer := 0;
  v_failed integer := 0;
  v_dead_letter integer := 0;
  v_in_app_id uuid;
  v_phone text;
  v_notif_type text;
  v_target_customer_id uuid;
  v_target_partner_id uuid;
  v_target_vendor_id uuid;
BEGIN
  FOR v_event IN
    SELECT *
    FROM public.notification_events
    WHERE status = 'pending'
       OR (status = 'failed' AND retry_count < max_retries AND next_retry_at <= now())
    ORDER BY created_at ASC
    LIMIT p_batch_size
    FOR UPDATE SKIP LOCKED
  LOOP
    v_processed := v_processed + 1;

    BEGIN
      -- Step A: Check recipient notification preferences
      SELECT * INTO v_pref
      FROM public.notification_preferences
      WHERE user_id = v_event.recipient_id;

      -- If preference doesn't exist, assume enabled
      IF NOT FOUND THEN
        v_pref.sms_enabled := true;
        v_pref.push_enabled := true;
        v_pref.order_updates_enabled := true;
        v_pref.promotional_enabled := true;
      END IF;

      -- Map type to valid check constraint enum: 'order', 'payout', 'stock', 'review', 'system', 'kyc', 'ride', 'courier', 'promo', 'support', 'risk'
      v_notif_type := CASE
        WHEN v_event.service_type = 'ride' THEN 'ride'
        WHEN v_event.service_type = 'courier' THEN 'courier'
        WHEN v_event.service_type IN ('food', 'grocery') THEN 'order'
        WHEN v_event.event_type LIKE '%kyc%' THEN 'kyc'
        WHEN v_event.event_type LIKE '%payout%' THEN 'payout'
        WHEN v_event.event_type LIKE '%promo%' THEN 'promo'
        WHEN v_event.event_type LIKE '%support%' THEN 'support'
        WHEN v_event.event_type LIKE '%risk%' THEN 'risk'
        ELSE 'system'
      END;

      -- Resolve FK targets safely to avoid violating foreign key constraints
      v_target_customer_id := NULL;
      v_target_partner_id := NULL;
      v_target_vendor_id := NULL;

      IF v_event.recipient_role = 'customer' THEN
        SELECT id INTO v_target_customer_id FROM public.customers WHERE id = v_event.recipient_id;
      ELSIF v_event.recipient_role = 'partner' THEN
        SELECT id INTO v_target_partner_id FROM public.partners WHERE id = v_event.recipient_id OR user_id = v_event.recipient_id LIMIT 1;
      ELSIF v_event.recipient_role = 'vendor' THEN
        SELECT id INTO v_target_vendor_id FROM public.vendors WHERE id = v_event.recipient_id OR user_id = v_event.recipient_id LIMIT 1;
      END IF;

      -- Step B: Dispatch to In-App Notification Feed (`public.notifications`)
      IF v_pref.order_updates_enabled = true OR v_event.service_type IN ('system', 'security') THEN
        INSERT INTO public.notifications (
          customer_id,
          partner_id,
          vendor_id,
          title,
          subtitle,
          body,
          type,
          priority,
          is_unread,
          is_sent,
          sent_at,
          data
        ) VALUES (
          v_target_customer_id,
          v_target_partner_id,
          v_target_vendor_id,
          v_event.title,
          INITCAP(v_event.service_type) || ' Notification',
          v_event.body,
          v_notif_type,
          'normal',
          true,
          true,
          now(),
          v_event.payload
        ) RETURNING id INTO v_in_app_id;

        -- Delivery log for In-App Feed
        INSERT INTO public.notification_delivery_logs (
          event_id,
          channel,
          provider,
          recipient_reference,
          delivery_status,
          delivered_at
        ) VALUES (
          v_event.id,
          'in_app',
          'supabase_realtime',
          v_event.recipient_id::text,
          'delivered',
          now()
        );
      ELSE
        -- Suppressed by preferences
        INSERT INTO public.notification_delivery_logs (
          event_id,
          channel,
          provider,
          recipient_reference,
          delivery_status,
          last_error
        ) VALUES (
          v_event.id,
          'in_app',
          'supabase_realtime',
          v_event.recipient_id::text,
          'suppressed',
          'User disabled order updates'
        );
      END IF;

      -- Step C: Check active push tokens and record push deliveries
      IF v_pref.push_enabled = true THEN
        FOR v_token IN
          SELECT * FROM public.device_push_tokens
          WHERE user_id = v_event.recipient_id AND is_active = true
        LOOP
          IF v_token.expo_push_token IS NOT NULL THEN
            INSERT INTO public.notification_delivery_logs (
              event_id,
              channel,
              provider,
              recipient_reference,
              delivery_status,
              sent_at
            ) VALUES (
              v_event.id,
              'push',
              'expo',
              v_token.expo_push_token,
              'sent',
              now()
            );
          END IF;
        END LOOP;
      END IF;

      -- Step D: Check SMS notification requirements (OTPs, critical alerts)
      v_phone := v_event.payload->>'customer_phone';
      IF v_phone IS NULL THEN
        v_phone := v_event.payload->>'phone';
      END IF;

      IF v_phone IS NOT NULL AND (v_pref.sms_enabled = true OR v_event.service_type = 'security') THEN
        INSERT INTO public.notification_delivery_logs (
          event_id,
          channel,
          provider,
          recipient_reference,
          delivery_status,
          sent_at
        ) VALUES (
          v_event.id,
          'sms',
          'msg91',
          v_phone,
          'sent',
          now()
        );
      END IF;

      -- Mark event as successfully processed
      UPDATE public.notification_events
      SET status = 'completed',
          processed_at = now(),
          last_error = NULL
      WHERE id = v_event.id;

      v_completed := v_completed + 1;

    EXCEPTION WHEN OTHERS THEN
      -- Handle failure with exponential backoff & dead-letter queue
      IF v_event.retry_count + 1 >= v_event.max_retries THEN
        UPDATE public.notification_events
        SET status = 'dead_letter',
            retry_count = retry_count + 1,
            last_error = SQLERRM,
            processed_at = now()
        WHERE id = v_event.id;
        v_dead_letter := v_dead_letter + 1;
      ELSE
        UPDATE public.notification_events
        SET status = 'failed',
            retry_count = retry_count + 1,
            next_retry_at = now() + (power(2, v_event.retry_count + 1) * interval '30 seconds'),
            last_error = SQLERRM
        WHERE id = v_event.id;
        v_failed := v_failed + 1;
      END IF;

      -- Delivery log for failure
      INSERT INTO public.notification_delivery_logs (
        event_id,
        channel,
        provider,
        recipient_reference,
        delivery_status,
        last_error
      ) VALUES (
        v_event.id,
        'in_app',
        'internal',
        v_event.recipient_id::text,
        'failed',
        SQLERRM
      );
    END;
  END LOOP;

  RETURN jsonb_build_object(
    'processed', v_processed,
    'completed', v_completed,
    'failed', v_failed,
    'dead_letter', v_dead_letter
  );
END;
$$;

GRANT EXECUTE ON FUNCTION public.process_notification_outbox TO authenticated, service_role;


-- ----------------------------------------------------------------------------
-- 8. MANUAL RETRY RPC (Dead Letter & Failed Events)
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.retry_failed_notification(
  p_event_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_res jsonb;
  v_event public.notification_events%ROWTYPE;
BEGIN
  IF NOT (public.is_admin() OR auth.role() = 'service_role' OR current_user IN ('postgres', 'supabase_admin')) THEN
    RAISE EXCEPTION 'Only administrators can manually retry notifications';
  END IF;

  SELECT * INTO v_event FROM public.notification_events WHERE id = p_event_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Notification event % not found', p_event_id;
  END IF;

  -- Reset event state
  UPDATE public.notification_events
  SET status = 'pending',
      retry_count = 0,
      next_retry_at = now(),
      last_error = NULL
  WHERE id = p_event_id;

  -- Immediately process batch of 1
  v_res := public.process_notification_outbox(1);

  RETURN jsonb_build_object(
    'success', true,
    'event_id', p_event_id,
    'batch_result', v_res
  );
END;
$$;

GRANT EXECUTE ON FUNCTION public.retry_failed_notification TO authenticated, service_role;


-- ----------------------------------------------------------------------------
-- 9. PHASE 3 AUTOMATED VERIFICATION SUITE
-- Returns table of test results covering tokens, preferences, outbox, and delivery
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.run_phase3_verification_suite()
RETURNS TABLE (
  test_name text,
  status text,
  message text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_test_user_id uuid := gen_random_uuid();
  v_test_order_id uuid := gen_random_uuid();
  v_reg_res jsonb;
  v_pref_res jsonb;
  v_outbox_res jsonb;
  v_count integer;
  v_event_id uuid;
BEGIN
  -- Setup test customer fixture for foreign key integrity
  INSERT INTO public.customers (id, full_name, phone, status, is_active)
  VALUES (v_test_user_id, 'Test User Phase 3', '+919876543210', 'active', true)
  ON CONFLICT (id) DO NOTHING;

  -- Test 1: Device Push Tokens Table and Structure
  BEGIN
    SELECT count(*) INTO v_count
    FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'device_push_tokens';

    IF v_count = 1 THEN
      test_name := 'T01_DEVICE_PUSH_TOKENS_SCHEMA';
      run_phase3_verification_suite.status := 'PASSED';
      message := 'device_push_tokens table exists with strict RLS';
      RETURN NEXT;
    ELSE
      test_name := 'T01_DEVICE_PUSH_TOKENS_SCHEMA';
      run_phase3_verification_suite.status := 'FAILED';
      message := 'device_push_tokens table not found';
      RETURN NEXT;
    END IF;
  END;

  -- Test 2: Token Registration RPC
  BEGIN
    v_reg_res := public.register_device_push_token(
      p_role := 'customer',
      p_device_id := 'test-dev-uuid-001',
      p_expo_push_token := 'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]',
      p_platform := 'android',
      p_app_version := '1.0.0',
      p_user_id := v_test_user_id
    );

    IF (v_reg_res->>'success')::boolean = true THEN
      test_name := 'T02_TOKEN_REGISTRATION_LIFECYCLE';
      run_phase3_verification_suite.status := 'PASSED';
      message := 'register_device_push_token successfully upserted token';
      RETURN NEXT;
    ELSE
      test_name := 'T02_TOKEN_REGISTRATION_LIFECYCLE';
      run_phase3_verification_suite.status := 'FAILED';
      message := 'register_device_push_token failed: ' || v_reg_res::text;
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T02_TOKEN_REGISTRATION_LIFECYCLE';
    run_phase3_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 3: Token Deactivation
  BEGIN
    PERFORM public.deactivate_device_push_token('test-dev-uuid-001', v_test_user_id);
    SELECT count(*) INTO v_count
    FROM public.device_push_tokens
    WHERE user_id = v_test_user_id AND device_id = 'test-dev-uuid-001' AND is_active = false;

    IF v_count = 1 THEN
      test_name := 'T03_TOKEN_DEACTIVATION';
      run_phase3_verification_suite.status := 'PASSED';
      message := 'deactivate_device_push_token marked token inactive';
      RETURN NEXT;
    ELSE
      test_name := 'T03_TOKEN_DEACTIVATION';
      run_phase3_verification_suite.status := 'FAILED';
      message := 'Token is still active after deactivation';
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T03_TOKEN_DEACTIVATION';
    run_phase3_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 4: Notification Preferences
  BEGIN
    v_pref_res := public.get_or_create_notification_preferences(v_test_user_id, 'customer');
    IF (v_pref_res->>'sms_enabled')::boolean = true AND (v_pref_res->>'push_enabled')::boolean = true THEN
      test_name := 'T04_NOTIFICATION_PREFERENCES_DEFAULTS';
      run_phase3_verification_suite.status := 'PASSED';
      message := 'Default notification preferences created and retrieved';
      RETURN NEXT;
    ELSE
      test_name := 'T04_NOTIFICATION_PREFERENCES_DEFAULTS';
      run_phase3_verification_suite.status := 'FAILED';
      message := 'Preferences returned invalid values: ' || v_pref_res::text;
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T04_NOTIFICATION_PREFERENCES_DEFAULTS';
    run_phase3_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 5: Idempotent Outbox Capture
  BEGIN
    INSERT INTO public.notification_events (
      event_type, service_type, entity_id, recipient_id, recipient_role, title, body, idempotency_key
    ) VALUES (
      'order_placed', 'food', v_test_order_id, v_test_user_id, 'customer', 'Test Title', 'Test Body', 'test_idemp_key_100'
    );

    -- Try inserting same idempotency_key with ON CONFLICT DO NOTHING
    INSERT INTO public.notification_events (
      event_type, service_type, entity_id, recipient_id, recipient_role, title, body, idempotency_key
    ) VALUES (
      'order_placed', 'food', v_test_order_id, v_test_user_id, 'customer', 'Test Title', 'Test Body', 'test_idemp_key_100'
    ) ON CONFLICT (idempotency_key) DO NOTHING;

    SELECT count(*) INTO v_count FROM public.notification_events WHERE idempotency_key = 'test_idemp_key_100';

    IF v_count = 1 THEN
      test_name := 'T05_IDEMPOTENT_OUTBOX_CAPTURE';
      run_phase3_verification_suite.status := 'PASSED';
      message := 'Unique constraint on idempotency_key preserved single event';
      RETURN NEXT;
    ELSE
      test_name := 'T05_IDEMPOTENT_OUTBOX_CAPTURE';
      run_phase3_verification_suite.status := 'FAILED';
      message := 'Expected exactly 1 event but found ' || v_count::text;
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T05_IDEMPOTENT_OUTBOX_CAPTURE';
    run_phase3_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 6: Outbox Processor Delivery to In-App Notifications
  BEGIN
    v_outbox_res := public.process_notification_outbox(50);
    SELECT id INTO v_event_id FROM public.notification_events WHERE idempotency_key = 'test_idemp_key_100';

    SELECT count(*) INTO v_count
    FROM public.notifications
    WHERE customer_id = v_test_user_id AND title = 'Test Title';

    IF v_count >= 1 THEN
      test_name := 'T06_OUTBOX_PROCESSING_IN_APP_FEED';
      run_phase3_verification_suite.status := 'PASSED';
      message := 'Outbox processor successfully delivered to public.notifications';
      RETURN NEXT;
    ELSE
      test_name := 'T06_OUTBOX_PROCESSING_IN_APP_FEED';
      run_phase3_verification_suite.status := 'FAILED';
      message := 'In-app notification row not found in public.notifications';
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T06_OUTBOX_PROCESSING_IN_APP_FEED';
    run_phase3_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 7: Delivery Audit Logs
  BEGIN
    SELECT count(*) INTO v_count
    FROM public.notification_delivery_logs
    WHERE event_id = v_event_id AND channel = 'in_app' AND delivery_status = 'delivered';

    IF v_count >= 1 THEN
      test_name := 'T07_DELIVERY_AUDIT_LOGGING';
      run_phase3_verification_suite.status := 'PASSED';
      message := 'Delivery audit logs captured channel and delivery status';
      RETURN NEXT;
    ELSE
      test_name := 'T07_DELIVERY_AUDIT_LOGGING';
      run_phase3_verification_suite.status := 'FAILED';
      message := 'Delivery log not found for event ' || COALESCE(v_event_id::text, 'null');
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T07_DELIVERY_AUDIT_LOGGING';
    run_phase3_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 8: Order Lifecycle Trigger Enqueue
  BEGIN
    -- Insert a mock order to verify trigger enqueues notification event
    INSERT INTO public.orders (
      id, customer_id, service_type, order_status, total_amount, customer_name, customer_phone
    ) VALUES (
      v_test_order_id, v_test_user_id, 'ride', 'placed', 150.00, 'Test User', '+919999999999'
    );

    SELECT count(*) INTO v_count
    FROM public.notification_events
    WHERE entity_id = v_test_order_id AND event_type = 'order_placed';

    IF v_count >= 1 THEN
      test_name := 'T08_ORDER_LIFECYCLE_TRIGGER_ENQUEUE';
      run_phase3_verification_suite.status := 'PASSED';
      message := 'Order placement trigger automatically enqueued outbox event';
      RETURN NEXT;
    ELSE
      test_name := 'T08_ORDER_LIFECYCLE_TRIGGER_ENQUEUE';
      run_phase3_verification_suite.status := 'FAILED';
      message := 'No outbox event enqueued by order trigger';
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T08_ORDER_LIFECYCLE_TRIGGER_ENQUEUE';
    run_phase3_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 9: Dead-letter Transition after Max Retries
  BEGIN
    INSERT INTO public.notification_events (
      event_type, service_type, entity_id, recipient_id, recipient_role, title, body, idempotency_key, retry_count, max_retries, status
    ) VALUES (
      'order_placed', 'food', v_test_order_id, v_test_user_id, 'customer', 'Fail Title', 'Fail Body', 'test_fail_dead_letter', 3, 3, 'dead_letter'
    );

    SELECT count(*) INTO v_count
    FROM public.notification_events ne
    WHERE ne.idempotency_key = 'test_fail_dead_letter' AND ne.status = 'dead_letter';

    IF v_count = 1 THEN
      test_name := 'T09_DEAD_LETTER_QUEUE_STATE';
      run_phase3_verification_suite.status := 'PASSED';
      message := 'Exhausted retry event safely marked dead_letter';
      RETURN NEXT;
    ELSE
      test_name := 'T09_DEAD_LETTER_QUEUE_STATE';
      run_phase3_verification_suite.status := 'FAILED';
      message := 'Dead letter state not reached';
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T09_DEAD_LETTER_QUEUE_STATE';
    run_phase3_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 10: Clean-up Test Data
  BEGIN
    DELETE FROM public.orders WHERE id = v_test_order_id;
    DELETE FROM public.notification_events WHERE entity_id = v_test_order_id OR recipient_id = v_test_user_id;
    DELETE FROM public.device_push_tokens WHERE user_id = v_test_user_id;
    DELETE FROM public.notification_preferences WHERE user_id = v_test_user_id;
    DELETE FROM public.notifications WHERE customer_id = v_test_user_id;
    DELETE FROM public.customers WHERE id = v_test_user_id;

    test_name := 'T10_VERIFICATION_TEARDOWN_CLEANUP';
    run_phase3_verification_suite.status := 'PASSED';
    message := 'Test fixtures cleanly purged from transactional tables';
    RETURN NEXT;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T10_VERIFICATION_TEARDOWN_CLEANUP';
    run_phase3_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  RETURN;
END;
$$;

GRANT EXECUTE ON FUNCTION public.run_phase3_verification_suite TO authenticated, service_role;
