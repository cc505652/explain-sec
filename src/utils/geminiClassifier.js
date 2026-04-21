export async function classifyThreatWithGemini(title, description) {
  const API_KEY = import.meta.env.VITE_GEMINI_API_KEY;

  // ✅ CORRECT MODEL: Picked directly from your console list
  const MODEL_NAME = "gemini-2.0-flash";
  
  const API_URL = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_NAME}:generateContent?key=${API_KEY}`;

  const prompt = `
    You are a cybersecurity SOC analyst.
    Classify the incident into ONE category: [phishing, malware, network, access, other].
    Assign urgency: [low, medium, high].
    
    Incident: ${title} - ${description}
    
    Respond with valid JSON only.
  `;

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { 
            response_mime_type: "application/json" 
        }
      })
    });

    if (!res.ok) {
      const errorText = await res.text();
      console.error(`Gemini API Error (${res.status}):`, errorText);
      throw new Error(`Gemini API Error: ${res.status}`);
    }

    const data = await res.json();
    let text = data.candidates?.[0]?.content?.parts?.[0]?.text || "{}";
    
    // Clean up any Markdown formatting if present
    text = text.replace(/```json|```/g, "").trim();

    const parsed = JSON.parse(text);

    return {
      category: parsed.category?.toLowerCase() || "other",
      urgency: parsed.urgency?.toLowerCase() || "low",
      reason: parsed.reason || "AI Classification",
      source: "gemini"
    };

  } catch (err) {
    console.warn("Gemini unavailable, using manual rules:", err);
    return null; // Fallback to Regex rules
  }
}