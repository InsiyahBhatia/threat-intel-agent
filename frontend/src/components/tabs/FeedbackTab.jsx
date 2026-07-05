import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

export default function FeedbackTab({ palette }) {
  const [feedbackList, setFeedbackList] = useState([]);
  const [loading, setLoading] = useState(false);
  const [retraining, setRetraining] = useState(false);
  const [retrainResult, setRetrainResult] = useState(null);

  useEffect(() => { fetchFeedback(); }, []);

  async function fetchFeedback() {
    setLoading(true);
    try {
      const r = await fetch(`${API_URL}/api/feedback`);
      if (r.ok) setFeedbackList(await r.json());
    } catch {}
    finally { setLoading(false); }
  }

  async function handleRetrain() {
    setRetraining(true); setRetrainResult(null);
    try {
      const r = await fetch(`${API_URL}/api/feedback/retrain`, { method: "POST" });
      const data = await r.json();
      setRetrainResult({ ok: r.ok, data });
    } catch (e) { setRetrainResult({ ok: false, data: { detail: e.message } }); }
    finally { setRetraining(false); }
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="bg-surface-light border border-border rounded-xl p-5"
    >
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-text">Online Learning &amp; Feedback</h3>
        <p className="text-xs text-muted mt-0.5">
          Review user corrections and retrain the model from collected feedback
        </p>
      </div>

      <div className="flex gap-2 mb-4">
        <button
          onClick={handleRetrain}
          disabled={retraining || !feedbackList.length}
          className={cn(
            "px-4 py-2 rounded-lg text-sm font-medium transition-all",
            "bg-primary hover:bg-primary-hover text-white",
            "disabled:opacity-40 disabled:cursor-not-allowed",
            "flex items-center gap-2"
          )}
        >
          {retraining ? (
            <><svg className="animate-spin w-4 h-4" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>Retraining...</>
          ) : `Retrain from ${feedbackList.length} feedbacks`}
        </button>
        <button
          onClick={fetchFeedback}
          disabled={loading}
          className="px-4 py-2 rounded-lg text-sm font-medium bg-surface border border-border hover:bg-border text-text disabled:opacity-40"
        >
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      {retrainResult && (
        <div className={cn("text-xs rounded-lg px-3 py-2 mb-3", retrainResult.ok ? "bg-green-500/10 text-green-500" : "bg-red-500/10 text-red-500")}>
          {retrainResult.ok ? (retrainResult.data.status || "Retrained successfully") : (retrainResult.data.detail || "Retrain failed")}
        </div>
      )}

      {loading && <div className="text-xs text-muted">Loading feedback...</div>}

      {!loading && feedbackList.length === 0 && (
        <div className="text-xs text-muted text-center py-6">No feedback collected yet</div>
      )}

      <div className="space-y-2 max-h-[500px] overflow-y-auto scrollbar-thin">
        {feedbackList.map((fb, i) => (
          <div key={fb.id || i} className="bg-surface rounded-lg px-3 py-2 border border-border text-xs space-y-1">
            <div className="flex items-center gap-2">
              <span className="font-mono font-semibold text-text">{fb.ioc}</span>
              <span className="text-muted">predicted:</span>
              <span className="font-medium">{fb.predicted_severity || fb.predicted_label}</span>
              <span className="text-muted">→ corrected:</span>
              <span className="font-medium text-green-500">{fb.corrected_severity || fb.correct_label}</span>
            </div>
            {fb.comment && <div className="text-muted italic">{fb.comment}</div>}
            <div className="text-[10px] text-muted">{fb.created_at || fb.timestamp}</div>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
