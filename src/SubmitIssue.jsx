import { useEffect, useState } from "react";
import {
  addDoc,
  collection,
  serverTimestamp,
  Timestamp
} from "firebase/firestore";
import { ref, uploadBytes, getDownloadURL } from "firebase/storage";

import { auth, db, storage } from "./firebase";
import { autoClassify, urgencyToScore } from "./utils/autoClassify";

export default function SubmitIssue() {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");

  // Manual selections
  const [category, setCategory] = useState("");
  const [urgency, setUrgency] = useState("");

  // AI suggestions (rule-based only)
  const [aiCategory, setAiCategory] = useState("analyzing...");
  const [aiUrgency, setAiUrgency] = useState("analyzing...");
  const [aiReason, setAiReason] = useState("");
  const [aiSource, setAiSource] = useState("detecting...");

  const [imageFile, setImageFile] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  /* 🧠 LIVE SMART DETECTION (Rule-based only) */
  useEffect(() => {
    // 1. Define the AI Logic
    const runAI = async () => {
      if (!title && !description) {
        setAiCategory("analyzing...");
        setAiUrgency("analyzing...");
        setAiSource(null);
        return;
      }

      setAiCategory("analyzing...");
      setAiUrgency("analyzing...");

      // Use rule-based classification only
      const rule = autoClassify(title, description);
      setAiCategory(rule.category);
      setAiUrgency(rule.urgency);
      setAiSource("rules");
    };

    // 2. Set a timer to wait 1 second after typing stops
    const timer = setTimeout(() => {
        if (title || description) {
            runAI();
        }
    }, 1000);

    // 3. Cleanup: If user types again before 1s, cancel the previous timer
    return () => clearTimeout(timer);
    
  }, [title, description]);


  const uploadIssueImage = async (userId) => {
    if (!imageFile) return null;
    const safeName = imageFile.name.replace(/\s+/g, "_");
    const path = `issue-images/${userId}/${Date.now()}_${safeName}`;
    const storageRef = ref(storage, path);
    await uploadBytes(storageRef, imageFile);
    const url = await getDownloadURL(storageRef);
    return { url, path, name: imageFile.name };
  };

  const submit = async (e) => {
    e.preventDefault();
    const user = auth.currentUser;
    if (!user) return alert("You are not logged in.");
    if (!title.trim()) return alert("Please enter a title.");

    setSubmitting(true);

    try {
      const finalCategory = category || aiCategory;
      const finalUrgency = urgency || aiUrgency;
      const urgencyScore = urgencyToScore(finalUrgency);

      // 🔹 ENHANCED AUTO-ASSIGNMENT: Use capability-aware system
      // Don't auto-assign on submission - let AdminDashboard handle it
      const autoAssignedTo = null; // Let auto-assignment engine handle this based on real users

      const img = await uploadIssueImage(user.uid);

      await addDoc(collection(db, "issues"), {
        title,
        description,
        category: finalCategory,
        urgency: finalUrgency,
        urgencyScore,
        location: "Campus Network",

        assignedTo: autoAssignedTo,
        status: "assigned",
        visibleTo: ["soc_l1"],
        escalatedTo: null,
        assignedAt: serverTimestamp(),
        assignedBy: "system",

        evidenceImage: img || null,

        escalated: false,
        escalatedAt: null,

        statusHistory: [
          { status: "open", at: Timestamp.now() },
          { status: "assigned", at: Timestamp.now(), note: `Auto-routed to ${autoAssignedTo}` }
        ],

        createdBy: user.uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),

        autoReason: aiReason,
        aiEngine: aiSource, // 🔥 shows if rules were used
        isDeleted: false
      });

      setTitle("");
      setDescription("");
      setCategory("");
      setUrgency("");
      setImageFile(null);
    } catch (err) {
      console.error(err);
      alert("Submit failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={submit} style={{ padding: 12 }}>
      <h3>Report Security Incident</h3>

      <input
        placeholder="Incident title"
        value={title}
        onChange={(e) => setTitle(e.target.value)}
      />

      <textarea
        placeholder="Describe what happened..."
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        rows={3}
      />

      {/* 🤖 ALWAYS VISIBLE AI PANEL */}
      <div style={{
        marginTop: 12,
        padding: "12px 16px",
        borderRadius: 14,
        background: "rgba(6,182,212,0.08)",
        border: "1px solid rgba(6,182,212,0.35)",
        display: "flex",
        flexDirection: "column",
        gap: 6
      }}>
        <div style={{ fontWeight: 600 }}>🤖 AI Threat Detection</div>

        <div style={{ display: "flex", gap: 10 }}>
          <span style={{
            background: "#0ea5e9",
            padding: "5px 12px",
            borderRadius: 999,
            fontWeight: 700
          }}>
            {aiCategory.toUpperCase()}
          </span>

          <span style={{
            background:
              aiUrgency === "high" ? "#ef4444" :
              aiUrgency === "medium" ? "#f59e0b" : "#10b981",
            padding: "5px 12px",
            borderRadius: 999,
            fontWeight: 700
          }}>
            {aiUrgency.toUpperCase()}
          </span>
        </div>

        <div style={{ fontSize: 12, opacity: 0.75 }}>
          Source: {aiSource === "rules" ? "📘 Rule-based Engine" :
                   "Analyzing..."}
        </div>

        {aiReason && (
          <div style={{ fontSize: 12, opacity: 0.7 }}>
            Reason: {aiReason}
          </div>
        )}
      </div>

      {/* 🧑 MANUAL OVERRIDE */}
      <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
        <select value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">Use AI Category</option>
          <option value="network">Network Attack</option>
          <option value="malware">Malware</option>
          <option value="phishing">Phishing</option>
          <option value="access">Unauthorized Access</option>
          <option value="other">Other</option>
        </select>

        <select value={urgency} onChange={(e) => setUrgency(e.target.value)}>
          <option value="">Use AI Urgency</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
        </select>
      </div>

      {/* 📎 Evidence Upload */}
      <div style={{ marginTop: 10 }}>
        <input
          type="file"
          accept="image/*"
          onChange={(e) => setImageFile(e.target.files?.[0] || null)}
        />
      </div>

      <button type="submit" disabled={submitting} style={{ marginTop: 14 }}>
        {submitting ? "Submitting..." : "Submit Incident"}
      </button>
    </form>
  );
}