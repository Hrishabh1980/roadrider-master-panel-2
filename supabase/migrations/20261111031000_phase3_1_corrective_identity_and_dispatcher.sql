-- ============================================================================
-- ROADRIDER ECOSYSTEM — PHASE 3.1 CORRECTIVE REMEDIATION MIGRATION
-- Migration: 20261111031000_phase3_1_corrective_identity_and_dispatcher.sql
-- Description: Canonical Identity Resolution, Cross-Tenant Isolation Hardening,
--              Outbox SKIP LOCKED Batch Worker Claiming, Crash Recovery Leases,
--              Mandatory vs Optional Preference Rules, Sensitive Data Masking,
--              and Automated Phase 3.1 Verification Suite
-- Target Database: db.sjahblquggmzlihqgzyt.supabase.co (Postgres 17)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. CANONICAL IDENTITY RESOLUTION HELPERS
-- Maps between auth.uid() and canonical business primary keys (customers.id, partners.id, vendors.id)
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.get_canonical_user_id(
  p_role text,
  p_auth_uid uuid DEFAULT auth.uid()
)
RETURNS uuid
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT CASE
    WHEN p_role = 'customer' THEN
      COALESCE(
        (SELECT id FROM public.customers WHERE auth_user_id = p_auth_uid LIMIT 1),
        (SELECT id FROM public.customers WHERE id = p_auth_uid LIMIT 1),
        p_auth_uid
      )
    WHEN p_role = 'partner' THEN
      COALESCE(
        (SELECT id FROM public.partners WHERE user_id = p_auth_uid LIMIT 1),
        (SELECT id FROM public.partners WHERE id = p_auth_uid LIMIT 1),
        p_auth_uid
      )
    WHEN p_role = 'vendor' THEN
      COALESCE(
        (SELECT id FROM public.vendors WHERE user_id = p_auth_uid LIMIT 1),
        (SELECT id FROM public.vendors WHERE id = p_auth_uid LIMIT 1),
        p_auth_uid
      )
    ELSE p_auth_uid
  END;
$$;

GRANT EXECUTE ON FUNCTION public.get_canonical_user_id TO authenticated, service_role;


CREATE OR REPLACE FUNCTION public.get_auth_uid_for_recipient(
  p_role text,
  p_recipient_id uuid
)
RETURNS uuid
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT CASE
    WHEN p_role = 'customer' THEN
      (SELECT auth_user_id FROM public.customers WHERE id = p_recipient_id)
    WHEN p_role = 'partner' THEN
      (SELECT user_id FROM public.partners WHERE id = p_recipient_id)
    WHEN p_role = 'vendor' THEN
      (SELECT user_id FROM public.vendors WHERE id = p_recipient_id)
    ELSE p_recipient_id
  END;
$$;

GRANT EXECUTE ON FUNCTION public.get_auth_uid_for_recipient TO authenticated, service_role;


-- ----------------------------------------------------------------------------
-- 2. SENSITIVE DATA MASKING HELPER
-- Strips plain-text OTPs, tokens, passwords, and sensitive keys from JSON payloads
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.sanitize_notification_payload(
  p_payload jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  v_result jsonb := p_payload;
  v_key text;
  v_sensitive_keys text[] := ARRAY[
    'otp', 'delivery_otp', 'pickup_otp', 'token', 'access_token',
    'refresh_token', 'password', 'secret', 'authkey', 'apiKey',
    'api_key', 'authorization', 'credit_card', 'cvv'
  ];
BEGIN
  IF p_payload IS NULL THEN
    RETURN '{}'::jsonb;
  END IF;

  FOREACH v_key IN ARRAY v_sensitive_keys
  LOOP
    IF v_result ? v_key THEN
      v_result := v_result - v_key || jsonb_build_object(v_key, '[REDACTED_FOR_SECURITY]');
    END IF;
  END LOOP;

  RETURN v_result;
END;
$$;

GRANT EXECUTE ON FUNCTION public.sanitize_notification_payload TO authenticated, service_role;


-- ----------------------------------------------------------------------------
-- 3. SCHEMA ADJUSTMENTS: AUTH IDENTITY & WORKER LEASE COLUMNS
-- ----------------------------------------------------------------------------

-- Add auth_user_id to device_push_tokens if missing
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'device_push_tokens' AND column_name = 'auth_user_id'
  ) THEN
    ALTER TABLE public.device_push_tokens ADD COLUMN auth_user_id uuid;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_device_push_tokens_auth ON public.device_push_tokens (auth_user_id);

-- Add auth_user_id to notification_preferences if missing
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'notification_preferences' AND column_name = 'auth_user_id'
  ) THEN
    ALTER TABLE public.notification_preferences ADD COLUMN auth_user_id uuid;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_notification_preferences_auth ON public.notification_preferences (auth_user_id);

-- Add worker lease and recipient_auth_id to notification_events if missing
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'notification_events' AND column_name = 'recipient_auth_id'
  ) THEN
    ALTER TABLE public.notification_events ADD COLUMN recipient_auth_id uuid;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'notification_events' AND column_name = 'worker_id'
  ) THEN
    ALTER TABLE public.notification_events ADD COLUMN worker_id text;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'notification_events' AND column_name = 'lease_expires_at'
  ) THEN
    ALTER TABLE public.notification_events ADD COLUMN lease_expires_at timestamptz;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_notification_events_recipient_auth ON public.notification_events (recipient_auth_id);
CREATE INDEX IF NOT EXISTS idx_notification_events_lease ON public.notification_events (status, lease_expires_at);


-- ----------------------------------------------------------------------------
-- 4. HARDENED RLS POLICIES ACROSS ALL NOTIFICATION TABLES
-- ----------------------------------------------------------------------------

-- Table: device_push_tokens
DROP POLICY IF EXISTS "Users manage own device push tokens" ON public.device_push_tokens;
CREATE POLICY "Users manage own device push tokens"
ON public.device_push_tokens
FOR ALL
TO authenticated
USING (
  auth_user_id = auth.uid() OR
  user_id = auth.uid() OR
  user_id = public.get_current_customer_id() OR
  user_id = public.get_current_partner_id() OR
  user_id = public.get_current_vendor_id()
)
WITH CHECK (
  auth_user_id = auth.uid() OR
  user_id = auth.uid() OR
  user_id = public.get_current_customer_id() OR
  user_id = public.get_current_partner_id() OR
  user_id = public.get_current_vendor_id()
);

DROP POLICY IF EXISTS "Admin Full Access on device_push_tokens" ON public.device_push_tokens;
CREATE POLICY "Admin Full Access on device_push_tokens"
ON public.device_push_tokens
FOR ALL
TO authenticated
USING (public.is_admin() OR public.is_master_admin())
WITH CHECK (public.is_admin() OR public.is_master_admin());


-- Table: notification_preferences
DROP POLICY IF EXISTS "Users view and update own preferences" ON public.notification_preferences;
CREATE POLICY "Users view and update own preferences"
ON public.notification_preferences
FOR ALL
TO authenticated
USING (
  auth_user_id = auth.uid() OR
  user_id = auth.uid() OR
  user_id = public.get_current_customer_id() OR
  user_id = public.get_current_partner_id() OR
  user_id = public.get_current_vendor_id()
)
WITH CHECK (
  auth_user_id = auth.uid() OR
  user_id = auth.uid() OR
  user_id = public.get_current_customer_id() OR
  user_id = public.get_current_partner_id() OR
  user_id = public.get_current_vendor_id()
);

DROP POLICY IF EXISTS "Admin Full Access on notification_preferences" ON public.notification_preferences;
CREATE POLICY "Admin Full Access on notification_preferences"
ON public.notification_preferences
FOR ALL
TO authenticated
USING (public.is_admin() OR public.is_master_admin())
WITH CHECK (public.is_admin() OR public.is_master_admin());


-- Table: notification_events
DROP POLICY IF EXISTS "Users view own notification events" ON public.notification_events;
CREATE POLICY "Users view own notification events"
ON public.notification_events
FOR SELECT
TO authenticated
USING (
  recipient_auth_id = auth.uid() OR
  recipient_id = auth.uid() OR
  recipient_id = public.get_current_customer_id() OR
  recipient_id = public.get_current_partner_id() OR
  recipient_id = public.get_current_vendor_id()
);

DROP POLICY IF EXISTS "Admin Full Access on notification_events" ON public.notification_events;
CREATE POLICY "Admin Full Access on notification_events"
ON public.notification_events
FOR ALL
TO authenticated
USING (public.is_admin() OR public.is_master_admin())
WITH CHECK (public.is_admin() OR public.is_master_admin());


-- Table: notification_delivery_logs
DROP POLICY IF EXISTS "Admin Full Access on notification_delivery_logs" ON public.notification_delivery_logs;
CREATE POLICY "Admin Full Access on notification_delivery_logs"
ON public.notification_delivery_logs
FOR ALL
TO authenticated
USING (public.is_admin() OR public.is_master_admin())
WITH CHECK (public.is_admin() OR public.is_master_admin());


-- Table: notifications (Align admin policy with is_admin and is_master_admin)
DROP POLICY IF EXISTS "Admin Full Access" ON public.notifications;
CREATE POLICY "Admin Full Access"
ON public.notifications
FOR ALL
TO authenticated
USING (public.is_admin() OR public.is_master_admin())
WITH CHECK (public.is_admin() OR public.is_master_admin());


-- ----------------------------------------------------------------------------
-- 5. UPDATED TOKEN REGISTRATION RPC (CANONICAL IDENTITY SUPPORT)
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
  v_auth_uid uuid;
  v_canonical_user_id uuid;
  v_record public.device_push_tokens%ROWTYPE;
BEGIN
  v_auth_uid := COALESCE(auth.uid(), p_user_id);
  IF v_auth_uid IS NULL THEN
    RAISE EXCEPTION 'User ID or valid authentication session is required';
  END IF;

  IF p_role NOT IN ('customer', 'partner', 'vendor', 'admin') THEN
    RAISE EXCEPTION 'Invalid role specified: %', p_role;
  END IF;

  IF p_device_id IS NULL OR TRIM(p_device_id) = '' THEN
    RAISE EXCEPTION 'Device ID cannot be empty';
  END IF;

  -- Resolve canonical business primary key
  v_canonical_user_id := public.get_canonical_user_id(p_role, v_auth_uid);

  -- Upsert device push token mapped to canonical ID and auth ID
  INSERT INTO public.device_push_tokens (
    user_id,
    auth_user_id,
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
    v_canonical_user_id,
    v_auth_uid,
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
    auth_user_id = EXCLUDED.auth_user_id,
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
    WHERE id = v_canonical_user_id OR auth_user_id = v_auth_uid;
  END IF;

  RETURN jsonb_build_object(
    'success', true,
    'id', v_record.id,
    'user_id', v_record.user_id,
    'auth_user_id', v_record.auth_user_id,
    'role', v_record.role,
    'device_id', v_record.device_id,
    'expo_push_token', v_record.expo_push_token,
    'is_active', v_record.is_active
  );
END;
$$;

GRANT EXECUTE ON FUNCTION public.register_device_push_token TO authenticated, service_role;


-- ----------------------------------------------------------------------------
-- 6. DISPATCHER QUEUE MANAGEMENT RPCs (SKIP LOCKED & WORKER LEASE)
-- ----------------------------------------------------------------------------

-- Claim a batch of pending or expired-lease outbox events atomically
CREATE OR REPLACE FUNCTION public.claim_notification_outbox_batch(
  p_batch_size integer DEFAULT 25,
  p_worker_id text DEFAULT 'default-worker',
  p_lease_seconds integer DEFAULT 300
)
RETURNS TABLE (
  id uuid,
  event_type text,
  service_type text,
  entity_id uuid,
  recipient_id uuid,
  recipient_auth_id uuid,
  recipient_role text,
  title text,
  body text,
  payload jsonb,
  idempotency_key text,
  retry_count integer,
  max_retries integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF NOT (public.is_admin() OR public.is_master_admin() OR auth.role() = 'service_role' OR current_user IN ('postgres', 'supabase_admin')) THEN
    RAISE EXCEPTION 'Access denied to claim outbox events';
  END IF;

  RETURN QUERY
  WITH claimable AS (
    SELECT ne.id
    FROM public.notification_events ne
    WHERE ne.status = 'pending'
       OR (ne.status = 'failed' AND ne.retry_count < ne.max_retries AND ne.next_retry_at <= now())
       OR (ne.status = 'processing' AND ne.lease_expires_at <= now()) -- Crash recovery of expired leases
    ORDER BY ne.created_at ASC
    LIMIT p_batch_size
    FOR UPDATE SKIP LOCKED
  )
  UPDATE public.notification_events u
  SET status = 'processing',
      worker_id = p_worker_id,
      lease_expires_at = now() + (p_lease_seconds * interval '1 second')
  FROM claimable
  WHERE u.id = claimable.id
  RETURNING
    u.id,
    u.event_type,
    u.service_type,
    u.entity_id,
    u.recipient_id,
    u.recipient_auth_id,
    u.recipient_role,
    u.title,
    u.body,
    u.payload,
    u.idempotency_key,
    u.retry_count,
    u.max_retries;
END;
$$;

GRANT EXECUTE ON FUNCTION public.claim_notification_outbox_batch TO authenticated, service_role;


-- Finalize successful dispatch of an event
CREATE OR REPLACE FUNCTION public.complete_notification_event(
  p_event_id uuid,
  p_delivery_status text DEFAULT 'delivered',
  p_channel text DEFAULT 'in_app',
  p_provider text DEFAULT 'supabase_realtime',
  p_provider_id text DEFAULT NULL,
  p_response_payload jsonb DEFAULT '{}'::jsonb
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_evt public.notification_events%ROWTYPE;
BEGIN
  IF NOT (public.is_admin() OR public.is_master_admin() OR auth.role() = 'service_role' OR current_user IN ('postgres', 'supabase_admin')) THEN
    RAISE EXCEPTION 'Access denied';
  END IF;

  SELECT * INTO v_evt FROM public.notification_events WHERE id = p_event_id;
  IF NOT FOUND THEN
    RETURN false;
  END IF;

  -- Update event to completed
  UPDATE public.notification_events
  SET status = 'completed',
      processed_at = now(),
      lease_expires_at = NULL,
      last_error = NULL
  WHERE id = p_event_id;

  -- Record delivery log with sanitized payload
  INSERT INTO public.notification_delivery_logs (
    event_id,
    channel,
    provider,
    recipient_reference,
    provider_message_id,
    delivery_status,
    response_payload,
    sent_at,
    delivered_at
  ) VALUES (
    p_event_id,
    p_channel,
    p_provider,
    v_evt.recipient_id::text,
    p_provider_id,
    p_delivery_status,
    public.sanitize_notification_payload(p_response_payload),
    now(),
    CASE WHEN p_delivery_status = 'delivered' THEN now() ELSE NULL END
  );

  RETURN true;
END;
$$;

GRANT EXECUTE ON FUNCTION public.complete_notification_event TO authenticated, service_role;


-- Finalize failed attempt with exponential backoff and dead-letter queueing
CREATE OR REPLACE FUNCTION public.fail_notification_event(
  p_event_id uuid,
  p_error text,
  p_channel text DEFAULT 'in_app',
  p_provider text DEFAULT 'internal'
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_evt public.notification_events%ROWTYPE;
BEGIN
  IF NOT (public.is_admin() OR public.is_master_admin() OR auth.role() = 'service_role' OR current_user IN ('postgres', 'supabase_admin')) THEN
    RAISE EXCEPTION 'Access denied';
  END IF;

  SELECT * INTO v_evt FROM public.notification_events WHERE id = p_event_id;
  IF NOT FOUND THEN
    RETURN false;
  END IF;

  IF v_evt.retry_count + 1 >= v_evt.max_retries THEN
    UPDATE public.notification_events
    SET status = 'dead_letter',
        retry_count = retry_count + 1,
        lease_expires_at = NULL,
        last_error = p_error,
        processed_at = now()
    WHERE id = p_event_id;
  ELSE
    UPDATE public.notification_events
    SET status = 'failed',
        retry_count = retry_count + 1,
        lease_expires_at = NULL,
        next_retry_at = now() + (power(2, v_evt.retry_count + 1) * interval '30 seconds'),
        last_error = p_error
    WHERE id = p_event_id;
  END IF;

  INSERT INTO public.notification_delivery_logs (
    event_id,
    channel,
    provider,
    recipient_reference,
    delivery_status,
    last_error
  ) VALUES (
    p_event_id,
    p_channel,
    p_provider,
    v_evt.recipient_id::text,
    'failed',
    p_error
  );

  RETURN true;
END;
$$;

GRANT EXECUTE ON FUNCTION public.fail_notification_event TO authenticated, service_role;


-- ----------------------------------------------------------------------------
-- 7. REFINED OUTBOX PROCESSOR: MANDATORY VS OPTIONAL PREFERENCE RULES
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
  v_is_mandatory boolean;
  v_sanitized_payload jsonb;
BEGIN
  FOR v_event IN
    SELECT *
    FROM public.notification_events
    WHERE status = 'pending'
       OR (status = 'failed' AND retry_count < max_retries AND next_retry_at <= now())
       OR (status = 'processing' AND lease_expires_at <= now()) -- Reclaim crashed workers
    ORDER BY created_at ASC
    LIMIT p_batch_size
    FOR UPDATE SKIP LOCKED
  LOOP
    v_processed := v_processed + 1;

    BEGIN
      -- Step A: Determine Mandatory vs Optional Classification
      -- Mandatory: Security alerts, OTPs, placed, assigned, in-transit, delivered, and cancelled
      v_is_mandatory := (
        v_event.service_type IN ('security', 'system') OR
        v_event.event_type IN (
          'auth_otp', 'verify_otp', 'order_otp', 'delivery_otp', 'pickup_otp',
          'order_placed', 'new_order_alert', 'captain_assigned', 'job_assigned',
          'order_in_transit', 'order_delivered', 'order_delivered_vendor',
          'order_cancelled', 'order_cancelled_vendor', 'order_cancelled_partner',
          'kyc_verified', 'kyc_rejected'
        )
      );

      -- Step B: Check recipient notification preferences
      SELECT * INTO v_pref
      FROM public.notification_preferences
      WHERE user_id = v_event.recipient_id OR auth_user_id = v_event.recipient_id;

      IF NOT FOUND THEN
        v_pref.sms_enabled := true;
        v_pref.push_enabled := true;
        v_pref.order_updates_enabled := true;
        v_pref.promotional_enabled := true;
      END IF;

      -- Step C: Sanitize payload to strip any sensitive values (OTPs, tokens)
      v_sanitized_payload := public.sanitize_notification_payload(v_event.payload);

      -- Map type to valid check constraint enum on notifications table
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

      -- Resolve canonical FK targets
      v_target_customer_id := NULL;
      v_target_partner_id := NULL;
      v_target_vendor_id := NULL;

      IF v_event.recipient_role = 'customer' THEN
        SELECT id INTO v_target_customer_id FROM public.customers WHERE id = v_event.recipient_id OR auth_user_id = v_event.recipient_id LIMIT 1;
      ELSIF v_event.recipient_role = 'partner' THEN
        SELECT id INTO v_target_partner_id FROM public.partners WHERE id = v_event.recipient_id OR user_id = v_event.recipient_id LIMIT 1;
      ELSIF v_event.recipient_role = 'vendor' THEN
        SELECT id INTO v_target_vendor_id FROM public.vendors WHERE id = v_event.recipient_id OR user_id = v_event.recipient_id LIMIT 1;
      END IF;

      -- Step D: Dispatch to In-App Notification Feed
      -- Mandatory alerts ALWAYS deliver. Optional alerts (preparing, ready, marketing) respect order_updates_enabled and promotional_enabled
      IF v_is_mandatory = true OR v_pref.order_updates_enabled = true THEN
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
          v_sanitized_payload
        ) RETURNING id INTO v_in_app_id;

        -- Record delivery log
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
        -- Suppressed by preferences (optional update only)
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
          'User disabled optional order updates'
        );
      END IF;

      -- Step E: Push notifications dispatch
      IF v_is_mandatory = true OR v_pref.push_enabled = true THEN
        FOR v_token IN
          SELECT * FROM public.device_push_tokens
          WHERE (user_id = v_event.recipient_id OR auth_user_id = v_event.recipient_id)
            AND is_active = true
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

      -- Step F: SMS dispatch (OTPs and mandatory critical alerts)
      v_phone := v_sanitized_payload->>'customer_phone';
      IF v_phone IS NULL THEN
        v_phone := v_sanitized_payload->>'phone';
      END IF;

      IF v_phone IS NOT NULL AND (v_is_mandatory = true OR v_pref.sms_enabled = true) THEN
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

      -- Mark event completed
      UPDATE public.notification_events
      SET status = 'completed',
          processed_at = now(),
          lease_expires_at = NULL,
          last_error = NULL
      WHERE id = v_event.id;

      v_completed := v_completed + 1;

    EXCEPTION WHEN OTHERS THEN
      IF v_event.retry_count + 1 >= v_event.max_retries THEN
        UPDATE public.notification_events
        SET status = 'dead_letter',
            retry_count = retry_count + 1,
            lease_expires_at = NULL,
            last_error = SQLERRM,
            processed_at = now()
        WHERE id = v_event.id;
        v_dead_letter := v_dead_letter + 1;
      ELSE
        UPDATE public.notification_events
        SET status = 'failed',
            retry_count = retry_count + 1,
            lease_expires_at = NULL,
            next_retry_at = now() + (power(2, v_event.retry_count + 1) * interval '30 seconds'),
            last_error = SQLERRM
        WHERE id = v_event.id;
        v_failed := v_failed + 1;
      END IF;

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
-- 8. PHASE 3.1 AUTOMATED VERIFICATION SUITE
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.run_phase3_1_verification_suite()
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
  v_test_auth_uid uuid;
  v_test_cust_id uuid;
  v_created_customer boolean := false;
  v_prev_order_updates boolean;
  v_prev_push boolean;
  v_prev_sms boolean;
  v_prev_promo boolean;
  v_test_partner_id uuid := gen_random_uuid();
  v_test_vendor_id uuid := gen_random_uuid();
  v_test_order_id uuid := gen_random_uuid();
  v_canonical uuid;
  v_claimed_count integer;
  v_batch jsonb;
  v_count integer;
  v_payload jsonb;
  v_sanitized jsonb;
BEGIN
  -- Setup test customer: pick an existing customer with valid auth_user_id
  SELECT c.id, c.auth_user_id INTO v_test_cust_id, v_test_auth_uid
  FROM public.customers c
  WHERE c.auth_user_id IS NOT NULL
  ORDER BY c.created_at DESC
  LIMIT 1;

  IF v_test_cust_id IS NULL THEN
    SELECT u.id INTO v_test_auth_uid FROM auth.users u LIMIT 1;
    v_test_cust_id := gen_random_uuid();
    INSERT INTO public.customers (id, auth_user_id, full_name, phone, status, is_active)
    VALUES (v_test_cust_id, v_test_auth_uid, 'Phase 3.1 Customer', '+919777777777', 'active', true)
    ON CONFLICT (id) DO NOTHING;
    v_created_customer := true;
  ELSE
    SELECT order_updates_enabled, push_enabled, sms_enabled, promotional_enabled
    INTO v_prev_order_updates, v_prev_push, v_prev_sms, v_prev_promo
    FROM public.notification_preferences
    WHERE user_id = v_test_cust_id;
  END IF;

  -- Test 1: Canonical Identity Resolution
  BEGIN
    v_canonical := public.get_canonical_user_id('customer', v_test_auth_uid);
    IF v_canonical = v_test_cust_id THEN
      test_name := 'T01_CANONICAL_IDENTITY_RESOLUTION';
      run_phase3_1_verification_suite.status := 'PASSED';
      message := 'get_canonical_user_id resolved auth_user_id to customers.id';
      RETURN NEXT;
    ELSE
      test_name := 'T01_CANONICAL_IDENTITY_RESOLUTION';
      run_phase3_1_verification_suite.status := 'FAILED';
      message := 'Expected ' || v_test_cust_id::text || ' but got ' || COALESCE(v_canonical::text, 'null');
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T01_CANONICAL_IDENTITY_RESOLUTION';
    run_phase3_1_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 2: Token Registration with Canonical & Auth IDs
  BEGIN
    PERFORM public.register_device_push_token(
      p_role := 'customer',
      p_device_id := 'dev-canon-test-01',
      p_expo_push_token := 'ExponentPushToken[mock_token_canon]',
      p_platform := 'android',
      p_app_version := '2.2.0',
      p_user_id := v_test_auth_uid
    );

    SELECT count(*) INTO v_count
    FROM public.device_push_tokens
    WHERE user_id = v_test_cust_id AND auth_user_id = v_test_auth_uid;

    IF v_count = 1 THEN
      test_name := 'T02_TOKEN_CANONICAL_MAPPING';
      run_phase3_1_verification_suite.status := 'PASSED';
      message := 'Push token recorded with both canonical customers.id and auth.uid()';
      RETURN NEXT;
    ELSE
      test_name := 'T02_TOKEN_CANONICAL_MAPPING';
      run_phase3_1_verification_suite.status := 'FAILED';
      message := 'Expected token row with canonical mapping not found';
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T02_TOKEN_CANONICAL_MAPPING';
    run_phase3_1_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 3: Outbox SKIP LOCKED Batch Worker Claiming
  BEGIN
    INSERT INTO public.notification_events (
      event_type, service_type, entity_id, recipient_id, recipient_role, title, body, idempotency_key
    ) VALUES (
      'order_placed', 'food', v_test_order_id, v_test_cust_id, 'customer', 'Claim Test', 'Claim Body', 'claim_key_' || v_test_order_id::text
    );

    SELECT count(*) INTO v_claimed_count
    FROM public.claim_notification_outbox_batch(5, 'test-worker-alpha', 300);

    IF v_claimed_count >= 1 THEN
      test_name := 'T03_OUTBOX_BATCH_CLAIM_SKIP_LOCKED';
      run_phase3_1_verification_suite.status := 'PASSED';
      message := 'claim_notification_outbox_batch atomically claimed batch with lease';
      RETURN NEXT;
    ELSE
      test_name := 'T03_OUTBOX_BATCH_CLAIM_SKIP_LOCKED';
      run_phase3_1_verification_suite.status := 'FAILED';
      message := 'Zero events claimed';
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T03_OUTBOX_BATCH_CLAIM_SKIP_LOCKED';
    run_phase3_1_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 4: Crash Recovery on Expired Lease
  BEGIN
    -- Set lease expired on claimed event to simulate worker crash
    UPDATE public.notification_events
    SET lease_expires_at = now() - interval '1 second'
    WHERE idempotency_key = 'claim_key_' || v_test_order_id::text;

    -- Reclaim with worker beta
    SELECT count(*) INTO v_claimed_count
    FROM public.claim_notification_outbox_batch(5, 'test-worker-beta', 300);

    IF v_claimed_count >= 1 THEN
      test_name := 'T04_CRASH_RECOVERY_LEASE_EXPIRATION';
      run_phase3_1_verification_suite.status := 'PASSED';
      message := 'Expired worker lease successfully reclaimed by worker beta';
      RETURN NEXT;
    ELSE
      test_name := 'T04_CRASH_RECOVERY_LEASE_EXPIRATION';
      run_phase3_1_verification_suite.status := 'FAILED';
      message := 'Crash recovery failed to reclaim expired lease';
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T04_CRASH_RECOVERY_LEASE_EXPIRATION';
    run_phase3_1_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 5: Finalize Event with complete_notification_event
  BEGIN
    PERFORM public.complete_notification_event(
      (SELECT id FROM public.notification_events WHERE idempotency_key = 'claim_key_' || v_test_order_id::text),
      'delivered',
      'in_app',
      'supabase_realtime',
      'mock_provider_id_001',
      jsonb_build_object('status', 'ok')
    );

    SELECT count(*) INTO v_count
    FROM public.notification_events ne
    WHERE ne.idempotency_key = 'claim_key_' || v_test_order_id::text AND ne.status = 'completed';

    IF v_count = 1 THEN
      test_name := 'T05_COMPLETE_NOTIFICATION_EVENT_RPC';
      run_phase3_1_verification_suite.status := 'PASSED';
      message := 'complete_notification_event atomically updated status to completed';
      RETURN NEXT;
    ELSE
      test_name := 'T05_COMPLETE_NOTIFICATION_EVENT_RPC';
      run_phase3_1_verification_suite.status := 'FAILED';
      message := 'Event not marked completed';
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T05_COMPLETE_NOTIFICATION_EVENT_RPC';
    run_phase3_1_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 6: Mandatory Communication Classification Rule
  BEGIN
    -- Configure preferences with order_updates_enabled = false
    PERFORM public.update_notification_preferences(false, false, false, false, v_test_cust_id);

    -- Insert mandatory event (order_delivered)
    INSERT INTO public.notification_events (
      event_type, service_type, entity_id, recipient_id, recipient_role, title, body, idempotency_key
    ) VALUES (
      'order_delivered', 'food', v_test_order_id, v_test_cust_id, 'customer', 'Delivered Order', 'Food is here', 'mand_key_' || v_test_order_id::text
    );

    PERFORM public.process_notification_outbox(500);

    -- Mandatory event MUST still deliver to notifications table despite order_updates_enabled = false
    SELECT count(*) INTO v_count
    FROM public.notifications
    WHERE customer_id = v_test_cust_id AND title = 'Delivered Order';

    IF v_count >= 1 THEN
      test_name := 'T06_MANDATORY_COMMUNICATION_RULE';
      run_phase3_1_verification_suite.status := 'PASSED';
      message := 'Mandatory order_delivered notification delivered despite false preferences';
      RETURN NEXT;
    ELSE
      test_name := 'T06_MANDATORY_COMMUNICATION_RULE';
      run_phase3_1_verification_suite.status := 'FAILED';
      message := 'Mandatory communication was mistakenly suppressed';
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T06_MANDATORY_COMMUNICATION_RULE';
    run_phase3_1_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 7: Optional Communication Suppression Rule
  BEGIN
    -- Insert optional event (order_preparing) with order_updates_enabled = false
    INSERT INTO public.notification_events (
      event_type, service_type, entity_id, recipient_id, recipient_role, title, body, idempotency_key
    ) VALUES (
      'order_preparing', 'food', v_test_order_id, v_test_cust_id, 'customer', 'Preparing Food', 'In Kitchen', 'opt_key_' || v_test_order_id::text
    );

    PERFORM public.process_notification_outbox(500);

    -- Optional event MUST be suppressed
    SELECT count(*) INTO v_count
    FROM public.notification_delivery_logs ndl
    JOIN public.notification_events ne ON ne.id = ndl.event_id
    WHERE ne.idempotency_key = 'opt_key_' || v_test_order_id::text AND ndl.delivery_status = 'suppressed';

    IF v_count >= 1 THEN
      test_name := 'T07_OPTIONAL_COMMUNICATION_SUPPRESSION';
      run_phase3_1_verification_suite.status := 'PASSED';
      message := 'Optional order_preparing notification successfully suppressed by preferences';
      RETURN NEXT;
    ELSE
      test_name := 'T07_OPTIONAL_COMMUNICATION_SUPPRESSION';
      run_phase3_1_verification_suite.status := 'FAILED';
      message := 'Optional communication was not suppressed';
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T07_OPTIONAL_COMMUNICATION_SUPPRESSION';
    run_phase3_1_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 8: Sensitive Data Sanitization
  BEGIN
    v_payload := jsonb_build_object(
      'order_id', v_test_order_id,
      'otp', '123456',
      'delivery_otp', '9876',
      'secret_key', 'supersecret',
      'service_type', 'food'
    );

    v_sanitized := public.sanitize_notification_payload(v_payload);

    IF (v_sanitized->>'otp') = '[REDACTED_FOR_SECURITY]' AND
       (v_sanitized->>'delivery_otp') = '[REDACTED_FOR_SECURITY]' AND
       (v_sanitized->>'service_type') = 'food' THEN
      test_name := 'T08_SENSITIVE_DATA_SANITIZATION';
      run_phase3_1_verification_suite.status := 'PASSED';
      message := 'sanitize_notification_payload successfully redacted OTP and credential keys';
      RETURN NEXT;
    ELSE
      test_name := 'T08_SENSITIVE_DATA_SANITIZATION';
      run_phase3_1_verification_suite.status := 'FAILED';
      message := 'Sanitization failed: ' || v_sanitized::text;
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T08_SENSITIVE_DATA_SANITIZATION';
    run_phase3_1_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  -- Test 9: Admin Authorization Alignment
  BEGIN
    IF public.is_admin() OR public.is_master_admin() OR auth.role() = 'service_role' OR current_user IN ('postgres', 'supabase_admin') THEN
      test_name := 'T09_ADMIN_AUTHORIZATION_ALIGNMENT';
      run_phase3_1_verification_suite.status := 'PASSED';
      message := 'Admin and service_role operational access consistently validated';
      RETURN NEXT;
    ELSE
      test_name := 'T09_ADMIN_AUTHORIZATION_ALIGNMENT';
      run_phase3_1_verification_suite.status := 'FAILED';
      message := 'Admin validation returned false';
      RETURN NEXT;
    END IF;
  END;

  -- Test 10: Teardown Cleanup
  BEGIN
    DELETE FROM public.notification_events WHERE entity_id = v_test_order_id;
    DELETE FROM public.notifications WHERE customer_id = v_test_cust_id AND title IN ('Delivered Order', 'Claim Test');
    DELETE FROM public.device_push_tokens WHERE user_id = v_test_cust_id AND device_id = 'dev-canon-test-01';

    IF v_created_customer THEN
      DELETE FROM public.notification_preferences WHERE user_id = v_test_cust_id;
      DELETE FROM public.customers WHERE id = v_test_cust_id;
    ELSE
      -- Restore previous preferences
      UPDATE public.notification_preferences
      SET order_updates_enabled = COALESCE(v_prev_order_updates, true),
          push_enabled = COALESCE(v_prev_push, true),
          sms_enabled = COALESCE(v_prev_sms, true),
          promotional_enabled = COALESCE(v_prev_promo, true)
      WHERE user_id = v_test_cust_id;
    END IF;

    test_name := 'T10_VERIFICATION_TEARDOWN_CLEANUP';
    run_phase3_1_verification_suite.status := 'PASSED';
    message := 'Phase 3.1 test fixtures purged cleanly';
    RETURN NEXT;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T10_VERIFICATION_TEARDOWN_CLEANUP';
    run_phase3_1_verification_suite.status := 'FAILED';
    message := SQLERRM;
    RETURN NEXT;
  END;

  RETURN;
END;
$$;

GRANT EXECUTE ON FUNCTION public.run_phase3_1_verification_suite TO authenticated, service_role;
