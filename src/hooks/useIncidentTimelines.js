/**
 * ======================================================================
 * useIncidentTimelines — Batch Timeline Fetch Hook
 * ======================================================================
 *
 * Phase: TIMELINE RENDERER MIGRATION (Microphase 1.6.2)
 *
 * PURPOSE:
 *   Fetches timeline events from the `incident_timeline` Firestore
 *   collection for a batch of incident IDs. Returns a Map of
 *   incidentId → events[].
 *
 * PERFORMANCE SAFETY:
 *   - ONE getDocs query per 30 incidents (Firestore `in` limit)
 *   - NO listeners (getDocs, not onSnapshot) — zero listener storms
 *   - 500ms debounce prevents rapid re-fetches
 *   - Stable ID comparison avoids unnecessary queries
 *   - Graceful degradation — returns empty Map on failure
 *
 * USAGE:
 *   const { timelines, loading } = useIncidentTimelines(incidentIds);
 *   const events = timelines.get(issueId) || [];
 *
 * ======================================================================
 */

import { useState, useEffect, useRef, useCallback } from "react";
import { collection, getDocs, query, where } from "firebase/firestore";
import { db, auth } from "../firebase";


/**
 * Batch-fetch timeline events for a list of incident IDs.
 *
 * @param {string[]} incidentIds - Array of incident document IDs
 * @param {string} [dependencyKey=""] - Optional string key to force refetch when issue properties change
 * @returns {{ timelines: Map<string, Array>, loading: boolean, refetch: Function }}
 */
export function useIncidentTimelines(incidentIds, dependencyKey = "") {
  const [timelines, setTimelines] = useState(() => new Map());
  const [loading, setLoading] = useState(false);
  const prevKeyRef = useRef("");
  const debounceRef = useRef(null);
  const mountedRef = useRef(true);

  // Refs for tracking retries
  const retryCountRef = useRef(0);
  const retryTimeoutRef = useRef(null);

  // Stable refetch function
  const fetchTimelines = useCallback(async (ids) => {
    if (!Array.isArray(ids) || ids.length === 0) {
      setTimelines(new Map());
      return;
    }

    setLoading(true);
    let hasError = false;
    let isAuthError = false;
    let errorDetail = "";

    try {
      const result = new Map();

      // Batch in groups of 30 (Firestore 'in' operator limit)
      for (let i = 0; i < ids.length; i += 30) {
        const batch = ids.slice(i, i + 30);

        try {
          const q = query(
            collection(db, "incident_timeline"),
            where("incidentId", "in", batch)
          );
          const snap = await getDocs(q);

          snap.forEach((docSnap) => {
            const data = docSnap.data();
            const id = data.incidentId;
            if (!result.has(id)) result.set(id, []);
            result.get(id).push(data);
          });
        } catch (batchErr) {
          hasError = true;
          errorDetail = batchErr?.message || "unknown error";
          if (batchErr?.code === "permission-denied") {
            isAuthError = true;
          }

          if (import.meta.env.DEV) {
            const authStatus = auth.currentUser ? `authenticated (UID: ${auth.currentUser.uid})` : "unauthenticated";
            console.warn(
              `[useIncidentTimelines] Batch query failed. Code: ${batchErr?.code || "unknown"}, ` +
              `Status: ${authStatus}, Error: ${errorDetail}`
            );
          }
        }
      }

      if (hasError) {
        // Safe retry logic for potential auth lag or transient issues
        if (retryCountRef.current < 3) {
          retryCountRef.current += 1;
          const delay = retryCountRef.current * 1000; // 1s, 2s, 3s linear backoff

          if (import.meta.env.DEV) {
            console.log(
              `[useIncidentTimelines] Scheduling query retry in ${delay}ms... (Attempt ${retryCountRef.current}/3)`
            );
          }

          if (retryTimeoutRef.current) clearTimeout(retryTimeoutRef.current);
          retryTimeoutRef.current = setTimeout(() => {
            fetchTimelines(ids);
          }, delay);
        } else {
          if (import.meta.env.DEV) {
            console.warn(
              "[useIncidentTimelines] Max fetch retries reached. Gracefully degrading with empty/partial timelines."
            );
          }
        }
      } else {
        // Reset retries upon fully successful fetch
        retryCountRef.current = 0;
      }

      // If we got some data (e.g. from successful batches) or no overall error, apply it
      if (mountedRef.current && (!hasError || result.size > 0)) {
        setTimelines(result);
      }
    } catch (err) {
      if (import.meta.env.DEV) {
        console.error("[useIncidentTimelines] Unexpected fetch execution error:", err);
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (debounceRef.current) clearTimeout(debounceRef.current);
      if (retryTimeoutRef.current) clearTimeout(retryTimeoutRef.current);
    };
  }, []);

  useEffect(() => {
    if (!Array.isArray(incidentIds) || incidentIds.length === 0) {
      setTimelines(new Map());
      return;
    }

    // Dedupe and sort IDs to create a stable key
    const uniqueIds = [...new Set(incidentIds)].sort();
    // Include current auth user context to detect login/logout and force freshness
    const currentUserUid = auth.currentUser?.uid || "anonymous";
    const key = uniqueIds.join(",") + (dependencyKey ? `|${dependencyKey}` : "") + `|usr:${currentUserUid}`;

    // Skip if IDs, dependencies, and user session haven't changed
    if (key === prevKeyRef.current) return;

    // Reset retry attempts on any explicit key change
    retryCountRef.current = 0;
    if (retryTimeoutRef.current) clearTimeout(retryTimeoutRef.current);

    // Debounce to avoid rapid re-fetches when listener fires frequently
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      prevKeyRef.current = key;
      fetchTimelines(uniqueIds);
    }, 500);

    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
      if (retryTimeoutRef.current) clearTimeout(retryTimeoutRef.current);
    };
  }, [incidentIds, dependencyKey, fetchTimelines, auth.currentUser?.uid]);

  // Manual refetch with optional delay to support detached fire-and-forget writes
  const refetch = useCallback((delayMs = 0) => {
    const uniqueIds = [...new Set(incidentIds || [])].sort();
    if (uniqueIds.length === 0) return;

    if (retryTimeoutRef.current) clearTimeout(retryTimeoutRef.current);

    if (delayMs > 0) {
      retryTimeoutRef.current = setTimeout(() => {
        fetchTimelines(uniqueIds);
      }, delayMs);
    } else {
      fetchTimelines(uniqueIds);
    }
  }, [incidentIds, fetchTimelines]);

  return { timelines, loading, refetch };
}

