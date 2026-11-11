-- ==============================================================================
-- ROADRIDER PHASE 3.2 — RECURSIVE SANITIZATION & BACKGROUND DISPATCHER MIGRATION
-- Migration: 20261111032000_phase3_2_recursive_sanitization_and_dispatcher.sql
-- ==============================================================================

-- 1. DROP AND RECREATE RECURSIVE PAYLOAD SANITIZER
DROP FUNCTION IF EXISTS public.sanitize_notification_payload(jsonb);

CREATE OR REPLACE FUNCTION public.sanitize_notification_payload(
  p_payload jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  v_type text;
  v_key text;
  v_val jsonb;
  v_sanitized_val jsonb;
  v_result jsonb;
  v_lower_key text;
BEGIN
  IF p_payload IS NULL THEN
    RETURN '{}'::jsonb;
  END IF;

  v_type := jsonb_typeof(p_payload);

  IF v_type = 'object' THEN
    IF p_payload = '{}'::jsonb THEN
      RETURN '{}'::jsonb;
    END IF;

    v_result := '{}'::jsonb;
    FOR v_key, v_val IN SELECT * FROM jsonb_each(p_payload)
    LOOP
      v_lower_key := lower(v_key);
      -- Check if key matches sensitive patterns case-insensitively
      IF v_lower_key IN (
          'otp', 'deliveryotp', 'delivery_otp', 'pickup_otp', 'pickupotp', 'pick_up_otp',
          'access_token', 'accesstoken', 'refresh_token', 'refreshtoken', 'token',
          'password', 'passwd', 'secret', 'authkey', 'auth_key', 'api_key', 'apikey',
          'authorization', 'credit_card', 'card_number', 'cardnumber', 'cvv', 'cvc',
          'pin', 'pan'
        )
        OR v_lower_key ~ '^(.*_)?(otp|password|secret|authkey|api_key|cvv|pin)$'
      THEN
        v_result := v_result || jsonb_build_object(v_key, '[REDACTED_FOR_SECURITY]'::text);
      ELSE
        IF jsonb_typeof(v_val) IN ('object', 'array') THEN
          v_sanitized_val := public.sanitize_notification_payload(v_val);
        ELSE
          v_sanitized_val := v_val;
        END IF;
        v_result := v_result || jsonb_build_object(v_key, v_sanitized_val);
      END IF;
    END LOOP;

    RETURN v_result;

  ELSIF v_type = 'array' THEN
    IF p_payload = '[]'::jsonb THEN
      RETURN '[]'::jsonb;
    END IF;

    SELECT COALESCE(jsonb_agg(public.sanitize_notification_payload(elem)), '[]'::jsonb)
    INTO v_result
    FROM jsonb_array_elements(p_payload) AS elem;

    RETURN v_result;

  ELSE
    RETURN p_payload;
  END IF;
END;
$$;

COMMENT ON FUNCTION public.sanitize_notification_payload(jsonb) IS 
'Phase 3.2: Recursively sanitizes JSONB objects and arrays, redacting sensitive keys case-insensitively.';

-- 2. IN-APP NOTIFICATION DISPATCH RPC
CREATE OR REPLACE FUNCTION public.dispatch_in_app_notification(
  p_event_id uuid
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_evt public.notification_events%ROWTYPE;
  v_clean_payload jsonb;
  v_notif_id uuid;
  v_notif_type text;
BEGIN
  IF NOT (public.is_admin() OR public.is_master_admin() OR auth.role() = 'service_role' OR current_user IN ('postgres', 'supabase_admin')) THEN
    RAISE EXCEPTION 'Access denied';
  END IF;

  SELECT * INTO v_evt FROM public.notification_events WHERE id = p_event_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Notification event not found: %', p_event_id;
  END IF;

  -- Recursively sanitize payload for in-app storage
  v_clean_payload := public.sanitize_notification_payload(v_evt.payload);

  -- Map service_type to valid notifications.type
  v_notif_type := CASE 
    WHEN v_evt.service_type IN ('food', 'grocery') THEN 'order'
    WHEN v_evt.service_type = 'ride' THEN 'ride'
    WHEN v_evt.service_type = 'courier' THEN 'courier'
    ELSE 'system'
  END;

  INSERT INTO public.notifications (
    customer_id,
    partner_id,
    vendor_id,
    title,
    body,
    type,
    priority,
    is_unread,
    is_sent,
    sent_at,
    data,
    created_at
  ) VALUES (
    CASE WHEN v_evt.recipient_role = 'customer' THEN v_evt.recipient_id ELSE NULL END,
    CASE WHEN v_evt.recipient_role = 'partner' THEN v_evt.recipient_id ELSE NULL END,
    CASE WHEN v_evt.recipient_role = 'vendor' THEN v_evt.recipient_id ELSE NULL END,
    v_evt.title,
    v_evt.body,
    v_notif_type,
    'normal',
    true,
    true,
    now(),
    v_clean_payload,
    now()
  )
  RETURNING id INTO v_notif_id;

  -- Record independent in-app delivery log
  INSERT INTO public.notification_delivery_logs (
    event_id,
    channel,
    provider,
    recipient_reference,
    provider_message_id,
    delivery_status,
    attempt_count,
    response_payload,
    sent_at,
    delivered_at
  ) VALUES (
    v_evt.id,
    'in_app',
    'supabase_realtime',
    v_evt.recipient_id::text,
    v_notif_id::text,
    'delivered',
    1,
    jsonb_build_object('notification_id', v_notif_id),
    now(),
    now()
  );

  RETURN v_notif_id;
END;
$$;

-- 3. RECORD INDEPENDENT DELIVERY LOG RPC
CREATE OR REPLACE FUNCTION public.record_notification_delivery_log(
  p_event_id uuid,
  p_channel text,
  p_provider text,
  p_recipient_reference text,
  p_provider_message_id text,
  p_delivery_status text,
  p_response_payload jsonb DEFAULT '{}'::jsonb,
  p_error text DEFAULT NULL
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_log_id uuid;
  v_sanitized_resp jsonb;
BEGIN
  IF NOT (public.is_admin() OR public.is_master_admin() OR auth.role() = 'service_role' OR current_user IN ('postgres', 'supabase_admin')) THEN
    RAISE EXCEPTION 'Access denied';
  END IF;

  v_sanitized_resp := public.sanitize_notification_payload(p_response_payload);

  INSERT INTO public.notification_delivery_logs (
    event_id,
    channel,
    provider,
    recipient_reference,
    provider_message_id,
    delivery_status,
    attempt_count,
    response_payload,
    last_error,
    sent_at,
    delivered_at
  ) VALUES (
    p_event_id,
    p_channel,
    p_provider,
    p_recipient_reference,
    p_provider_message_id,
    p_delivery_status,
    1,
    v_sanitized_resp,
    p_error,
    now(),
    CASE WHEN p_delivery_status = 'delivered' THEN now() ELSE NULL END
  )
  RETURNING id INTO v_log_id;

  RETURN v_log_id;
END;
$$;

-- 4. DEACTIVATE INVALID EXPO PUSH TOKEN RPC
CREATE OR REPLACE FUNCTION public.deactivate_expo_push_token(
  p_expo_push_token text,
  p_reason text DEFAULT 'DeviceNotRegistered'
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF NOT (public.is_admin() OR public.is_master_admin() OR auth.role() = 'service_role' OR current_user IN ('postgres', 'supabase_admin')) THEN
    RAISE EXCEPTION 'Access denied';
  END IF;

  UPDATE public.device_push_tokens
  SET is_active = false,
      updated_at = now()
  WHERE expo_push_token = p_expo_push_token;

  RETURN FOUND;
END;
$$;

-- 5. RECOVER EXPIRED WORKER LEASES RPC
CREATE OR REPLACE FUNCTION public.recover_expired_notification_leases()
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_recovered_count integer;
BEGIN
  IF NOT (public.is_admin() OR public.is_master_admin() OR auth.role() = 'service_role' OR current_user IN ('postgres', 'supabase_admin')) THEN
    RAISE EXCEPTION 'Access denied';
  END IF;

  UPDATE public.notification_events
  SET status = 'pending',
      worker_id = NULL,
      lease_expires_at = NULL,
      last_error = COALESCE(last_error, 'Lease expired and recovered by coordinator')
  WHERE status = 'processing'
    AND lease_expires_at <= now();

  GET DIAGNOSTICS v_recovered_count = ROW_COUNT;
  RETURN v_recovered_count;
END;
$$;

-- 6. PHASE 3.2 VERIFICATION SUITE
CREATE OR REPLACE FUNCTION public.run_phase3_2_verification_suite()
RETURNS TABLE (
  test_name text,
  status text,
  details text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_sample_nested jsonb;
  v_clean_nested jsonb;
  v_sample_array jsonb;
  v_clean_array jsonb;
  v_sample_casing jsonb;
  v_clean_casing jsonb;
  v_test_event_id uuid;
  v_test_cust_id uuid;
  v_test_auth_id uuid;
  v_claimed_count integer;
  v_recovered_count integer;
  v_notif_id uuid;
  v_log_count integer;
BEGIN
  -- Test 1: Recursive Sanitization of Nested Object
  BEGIN
    v_sample_nested := jsonb_build_object(
      'order_id', gen_random_uuid(),
      'amount', 250,
      'order', jsonb_build_object(
        'deliveryOtp', '123456',
        'inner', jsonb_build_object(
          'secret', 'super_secret_value',
          'note', 'handle with care'
        )
      )
    );
    v_clean_nested := public.sanitize_notification_payload(v_sample_nested);

    IF (v_clean_nested->'order'->>'deliveryOtp') = '[REDACTED_FOR_SECURITY]' AND
       (v_clean_nested->'order'->'inner'->>'secret') = '[REDACTED_FOR_SECURITY]' AND
       (v_clean_nested->'order'->'inner'->>'note') = 'handle with care' THEN
      test_name := 'T01_RECURSIVE_SANITIZATION_NESTED_OBJECT';
      status := 'PASS';
      details := 'Deeply nested sensitive keys redacted while non-sensitive preserved';
      RETURN NEXT;
    ELSE
      test_name := 'T01_RECURSIVE_SANITIZATION_NESTED_OBJECT';
      status := 'FAIL';
      details := 'Nested redaction failed: ' || v_clean_nested::text;
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T01_RECURSIVE_SANITIZATION_NESTED_OBJECT';
    status := 'FAIL';
    details := 'Exception: ' || SQLERRM;
    RETURN NEXT;
  END;

  -- Test 2: Recursive Sanitization of Arrays of Objects
  BEGIN
    v_sample_array := jsonb_build_array(
      jsonb_build_object('item', 'pizza', 'otp', '9999'),
      jsonb_build_object('item', 'burger', 'password', 'mypassword123')
    );
    v_clean_array := public.sanitize_notification_payload(v_sample_array);

    IF (v_clean_array->0->>'otp') = '[REDACTED_FOR_SECURITY]' AND
       (v_clean_array->0->>'item') = 'pizza' AND
       (v_clean_array->1->>'password') = '[REDACTED_FOR_SECURITY]' AND
       (v_clean_array->1->>'item') = 'burger' THEN
      test_name := 'T02_RECURSIVE_SANITIZATION_ARRAY_OF_OBJECTS';
      status := 'PASS';
      details := 'Array of objects sanitized recursively';
      RETURN NEXT;
    ELSE
      test_name := 'T02_RECURSIVE_SANITIZATION_ARRAY_OF_OBJECTS';
      status := 'FAIL';
      details := 'Array redaction failed: ' || v_clean_array::text;
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T02_RECURSIVE_SANITIZATION_ARRAY_OF_OBJECTS';
    status := 'FAIL';
    details := 'Exception: ' || SQLERRM;
    RETURN NEXT;
  END;

  -- Test 3: Case-Insensitive Sensitive Key Redaction
  BEGIN
    v_sample_casing := jsonb_build_object(
      'DELIVERYOTP', '1111',
      'ApiKey', 'key_12345',
      'AuthKey', 'auth_secret',
      'cAsE_tEsT', 'normal_value'
    );
    v_clean_casing := public.sanitize_notification_payload(v_sample_casing);

    IF (v_clean_casing->>'DELIVERYOTP') = '[REDACTED_FOR_SECURITY]' AND
       (v_clean_casing->>'ApiKey') = '[REDACTED_FOR_SECURITY]' AND
       (v_clean_casing->>'AuthKey') = '[REDACTED_FOR_SECURITY]' AND
       (v_clean_casing->>'cAsE_tEsT') = 'normal_value' THEN
      test_name := 'T03_RECURSIVE_SANITIZATION_CASE_INSENSITIVE';
      status := 'PASS';
      details := 'Case-insensitive sensitive keys properly redacted';
      RETURN NEXT;
    ELSE
      test_name := 'T03_RECURSIVE_SANITIZATION_CASE_INSENSITIVE';
      status := 'FAIL';
      details := 'Case insensitivity failed: ' || v_clean_casing::text;
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T03_RECURSIVE_SANITIZATION_CASE_INSENSITIVE';
    status := 'FAIL';
    details := 'Exception: ' || SQLERRM;
    RETURN NEXT;
  END;

  -- Test 4: Preserves Non-Sensitive Keys and Types
  BEGIN
    v_sample_nested := jsonb_build_object(
      'order_number', 'RR-9921',
      'count', 42,
      'is_active', true,
      'empty_obj', jsonb_build_object(),
      'empty_arr', jsonb_build_array()
    );
    v_clean_nested := public.sanitize_notification_payload(v_sample_nested);

    IF (v_clean_nested->>'order_number') = 'RR-9921' AND
       (v_clean_nested->>'count') = '42' AND
       (v_clean_nested->>'is_active') = 'true' AND
       (v_clean_nested->'empty_obj') = '{}'::jsonb AND
       (v_clean_nested->'empty_arr') = '[]'::jsonb THEN
      test_name := 'T04_RECURSIVE_SANITIZATION_PRESERVES_NON_SENSITIVE';
      status := 'PASS';
      details := 'Non-sensitive keys, scalar types, and empty structures preserved';
      RETURN NEXT;
    ELSE
      test_name := 'T04_RECURSIVE_SANITIZATION_PRESERVES_NON_SENSITIVE';
      status := 'FAIL';
      details := 'Structure preservation failed: ' || v_clean_nested::text;
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T04_RECURSIVE_SANITIZATION_PRESERVES_NON_SENSITIVE';
    status := 'FAIL';
    details := 'Exception: ' || SQLERRM;
    RETURN NEXT;
  END;

  -- Test 5: Claim Batch SKIP LOCKED and Worker Lease
  BEGIN
    SELECT c.id, c.auth_user_id INTO v_test_cust_id, v_test_auth_id
    FROM public.customers c WHERE c.auth_user_id IS NOT NULL LIMIT 1;

    INSERT INTO public.notification_events (
      event_type, service_type, entity_id, recipient_id, recipient_auth_id,
      recipient_role, title, body, payload, idempotency_key, status
    ) VALUES (
      'test_worker_claim', 'food', gen_random_uuid(), v_test_cust_id, v_test_auth_id,
      'customer', 'Test Claim', 'Worker lease test',
      jsonb_build_object('deliveryOtp', '4321', 'note', 'worker test'),
      'test_worker_claim_' || gen_random_uuid()::text, 'pending'
    )
    RETURNING id INTO v_test_event_id;

    SELECT count(*) INTO v_claimed_count
    FROM public.claim_notification_outbox_batch(10, 'worker-alpha', 60)
    WHERE id = v_test_event_id;

    IF v_claimed_count = 1 THEN
      test_name := 'T05_CLAIM_BATCH_SKIP_LOCKED_CONCURRENCY';
      status := 'PASS';
      details := 'Outbox batch claimed atomically with worker lease';
      RETURN NEXT;
    ELSE
      test_name := 'T05_CLAIM_BATCH_SKIP_LOCKED_CONCURRENCY';
      status := 'FAIL';
      details := 'Failed to claim event atomically';
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T05_CLAIM_BATCH_SKIP_LOCKED_CONCURRENCY';
    status := 'FAIL';
    details := 'Exception: ' || SQLERRM;
    RETURN NEXT;
  END;

  -- Test 6: Expired Lease Recovery
  BEGIN
    -- Artificially expire the lease of the event
    UPDATE public.notification_events
    SET lease_expires_at = now() - interval '10 seconds'
    WHERE id = v_test_event_id;

    v_recovered_count := public.recover_expired_notification_leases();

    IF v_recovered_count >= 1 THEN
      test_name := 'T06_EXPIRED_LEASE_RECOVERY';
      status := 'PASS';
      details := 'Expired worker leases recovered successfully';
      RETURN NEXT;
    ELSE
      test_name := 'T06_EXPIRED_LEASE_RECOVERY';
      status := 'FAIL';
      details := 'No expired leases recovered';
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T06_EXPIRED_LEASE_RECOVERY';
    status := 'FAIL';
    details := 'Exception: ' || SQLERRM;
    RETURN NEXT;
  END;

  -- Test 7: Dead Letter Routing upon Exceeding Max Retries
  BEGIN
    -- Set retry count close to max
    UPDATE public.notification_events
    SET retry_count = 2, max_retries = 3
    WHERE id = v_test_event_id;

    PERFORM public.fail_notification_event(
      v_test_event_id,
      'Simulated persistent fatal delivery error',
      'push',
      'expo'
    );

    IF EXISTS (
      SELECT 1 FROM public.notification_events ne
      WHERE ne.id = v_test_event_id AND ne.status = 'dead_letter'
    ) THEN
      test_name := 'T07_DEAD_LETTER_ROUTING';
      status := 'PASS';
      details := 'Event successfully transitioned to dead_letter status';
      RETURN NEXT;
    ELSE
      test_name := 'T07_DEAD_LETTER_ROUTING';
      status := 'FAIL';
      details := 'Event was not transitioned to dead_letter';
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T07_DEAD_LETTER_ROUTING';
    status := 'FAIL';
    details := 'Exception: ' || SQLERRM;
    RETURN NEXT;
  END;

  -- Test 8: In-App Notification Dispatch and Feed Insertion
  BEGIN
    -- Create fresh event for in-app dispatch test
    INSERT INTO public.notification_events (
      event_type, service_type, entity_id, recipient_id, recipient_auth_id,
      recipient_role, title, body, payload, idempotency_key, status
    ) VALUES (
      'order_ready', 'food', gen_random_uuid(), v_test_cust_id, v_test_auth_id,
      'customer', 'Your Food is Ready', 'Pick up at counter',
      jsonb_build_object('deliveryOtp', '8888', 'food_item', 'Burger Combo'),
      'test_in_app_' || gen_random_uuid()::text, 'processing'
    )
    RETURNING id INTO v_test_event_id;

    v_notif_id := public.dispatch_in_app_notification(v_test_event_id);

    IF v_notif_id IS NOT NULL AND EXISTS (
      SELECT 1 FROM public.notifications n
      WHERE n.id = v_notif_id 
        AND (n.data->>'deliveryOtp') = '[REDACTED_FOR_SECURITY]'
        AND (n.data->>'food_item') = 'Burger Combo'
    ) THEN
      test_name := 'T08_IN_APP_DISPATCH_AND_FEED_SANITIZATION';
      status := 'PASS';
      details := 'In-app notification created with sanitized payload in feed';
      RETURN NEXT;
    ELSE
      test_name := 'T08_IN_APP_DISPATCH_AND_FEED_SANITIZATION';
      status := 'FAIL';
      details := 'In-app dispatch failed or payload not sanitized';
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T08_IN_APP_DISPATCH_AND_FEED_SANITIZATION';
    status := 'FAIL';
    details := 'Exception: ' || SQLERRM;
    RETURN NEXT;
  END;

  -- Test 9: Independent Multi-Channel Delivery Logs
  BEGIN
    -- Record independent logs for push and sms
    PERFORM public.record_notification_delivery_log(
      v_test_event_id,
      'push',
      'expo',
      'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]',
      'ticket_12345',
      'delivered',
      jsonb_build_object('status', 'ok')
    );

    PERFORM public.record_notification_delivery_log(
      v_test_event_id,
      'sms',
      'msg91',
      '+919876543210',
      'msg_req_9988',
      'delivered',
      jsonb_build_object('type', 'success')
    );

    SELECT count(*) INTO v_log_count
    FROM public.notification_delivery_logs ndl
    WHERE ndl.event_id = v_test_event_id;

    IF v_log_count >= 3 THEN -- in_app + push + sms
      test_name := 'T09_MULTI_CHANNEL_INDEPENDENT_LOGS';
      status := 'PASS';
      details := 'All 3 delivery channels logged independently with full provider context';
      RETURN NEXT;
    ELSE
      test_name := 'T09_MULTI_CHANNEL_INDEPENDENT_LOGS';
      status := 'FAIL';
      details := 'Expected >= 3 delivery logs, found: ' || v_log_count::text;
      RETURN NEXT;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T09_MULTI_CHANNEL_INDEPENDENT_LOGS';
    status := 'FAIL';
    details := 'Exception: ' || SQLERRM;
    RETURN NEXT;
  END;

  -- Test 10: Device Push Token Deactivation on DeviceNotRegistered
  BEGIN
    INSERT INTO public.device_push_tokens (
      user_id, role, device_id, expo_push_token, is_active
    ) VALUES (
      COALESCE(v_test_auth_id, gen_random_uuid()), 'customer',
      'test_device_' || gen_random_uuid()::text,
      'ExponentPushToken[InvalidTokenForTesting]', true
    )
    ON CONFLICT (user_id, device_id) DO UPDATE SET expo_push_token = EXCLUDED.expo_push_token;

    PERFORM public.deactivate_expo_push_token('ExponentPushToken[InvalidTokenForTesting]');

    IF EXISTS (
      SELECT 1 FROM public.device_push_tokens dpt
      WHERE dpt.expo_push_token = 'ExponentPushToken[InvalidTokenForTesting]'
        AND dpt.is_active = false
    ) THEN
      test_name := 'T10_DEVICE_TOKEN_DEACTIVATION';
      status := 'PASS';
      details := 'Unregistered device push tokens deactivated cleanly';
      RETURN NEXT;
    ELSE
      test_name := 'T10_DEVICE_TOKEN_DEACTIVATION';
      status := 'FAIL';
      details := 'Failed to deactivate invalid token';
      RETURN NEXT;
    END IF;

    -- Cleanup test token
    DELETE FROM public.device_push_tokens WHERE expo_push_token = 'ExponentPushToken[InvalidTokenForTesting]';
  EXCEPTION WHEN OTHERS THEN
    test_name := 'T10_DEVICE_TOKEN_DEACTIVATION';
    status := 'FAIL';
    details := 'Exception: ' || SQLERRM;
    RETURN NEXT;
  END;

  -- Cleanup test notification event and logs
  DELETE FROM public.notification_events WHERE id = v_test_event_id;

END;
$$;
