import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Lock, 
  Globe, 
  Search, 
  Info, 
  ArrowRight,
  ExternalLink,
  ChevronRight,
  ShieldIcon
} from 'lucide-react';

// --- Configuration ---
const apiKey = ""; // Environment handles this
const MODEL_NAME = "gemini-2.5-flash-preview-09-2025";

const App = () => {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [language, setLanguage] = useState('en'); // 'en' or 'hi'
  const [error, setError] = useState(null);

  // System Prompt for Cybersecurity Expert AI
  const systemPrompt = `
    You are CyberRakshak AI, an expert cybersecurity analyst. 
    Analyze the provided text (SMS, Email, or Link) for phishing, scams, or fraud.
    
    Return a JSON object with the following structure:
    {
      "riskLevel": "Safe" | "Suspicious" | "Dangerous",
      "score": number (0-100),
      "explanation_en": "Simple explanation in English",
      "explanation_hi": "Simple explanation in Hindi",
      "tips_en": ["Tip 1", "Tip 2", "Tip 3"],
      "tips_hi": ["सुझाव 1", "सुझाव 2", "सुझाव 3"],
      "indicators": ["Suspicious link", "Urgent tone", etc.]
    }
    Be objective and prioritize user safety.
  `;

  const analyzeThreat = async () => {
    if (!input.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    let retries = 0;
    const maxRetries = 5;

    const attemptAnalysis = async () => {
      try {
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${MODEL_NAME}:generateContent?key=${apiKey}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [{ text: `Analyze this content: ${input}` }] }],
            systemInstruction: { parts: [{ text: systemPrompt }] },
            generationConfig: { responseMimeType: "application/json" }
          })
        });

        if (!response.ok) throw new Error('API request failed');

        const data = await response.json();
        const analysis = JSON.parse(data.candidates[0].content.parts[0].text);
        setResult(analysis);
      } catch (err) {
        if (retries < maxRetries) {
          retries++;
          const delay = Math.pow(2, retries) * 500;
          await new Promise(res => setTimeout(res, delay));
          return attemptAnalysis();
        }
        setError(language === 'en' ? "Failed to analyze. Please try again." : "विश्लेषण करने में विफल। कृपया पुन: प्रयास करें।");
      } finally {
        setLoading(false);
      }
    };

    await attemptAnalysis();
  };

  const getRiskColor = (level) => {
    switch (level) {
      case 'Safe': return 'text-emerald-500 bg-emerald-50 border-emerald-200';
      case 'Suspicious': return 'text-amber-500 bg-amber-50 border-amber-200';
      case 'Dangerous': return 'text-red-500 bg-red-50 border-red-200';
      default: return 'text-slate-500 bg-slate-50 border-slate-200';
    }
  };

  const getRiskIcon = (level) => {
    switch (level) {
      case 'Safe': return <ShieldCheck className="w-8 h-8" />;
      case 'Suspicious': return <AlertTriangle className="w-8 h-8" />;
      case 'Dangerous': return <ShieldAlert className="w-8 h-8" />;
      default: return <Search className="w-8 h-8" />;
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 font-sans text-slate-900 pb-12">
      {/* Header */}
      <nav className="bg-white border-b border-slate-200 sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="bg-blue-600 p-2 rounded-lg">
              <ShieldIcon className="text-white w-6 h-6" />
            </div>
            <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-indigo-600">
              CyberRakshak AI
            </h1>
          </div>
          <button 
            onClick={() => setLanguage(language === 'en' ? 'hi' : 'en')}
            className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-slate-200 hover:bg-slate-50 transition-colors text-sm font-medium"
          >
            <Globe className="w-4 h-4 text-blue-600" />
            {language === 'en' ? 'हिन्दी' : 'English'}
          </button>
        </div>
      </nav>

      <main className="max-w-3xl mx-auto px-4 mt-8">
        {/* Hero Section */}
        <div className="text-center mb-10">
          <h2 className="text-3xl font-extrabold text-slate-900 mb-3">
            {language === 'en' ? 'Stop Cyber Scams Before They Start' : 'साइबर घोटालों को शुरू होने से पहले रोकें'}
          </h2>
          <p className="text-slate-600 max-w-lg mx-auto">
            {language === 'en' 
              ? 'Paste any SMS, Email body, or link to check for potential threats using advanced AI.' 
              : 'किसी भी एसएमएस, ईमेल या लिंक को पेस्ट करें और उन्नत एआई का उपयोग करके संभावित खतरों की जांच करें।'}
          </p>
        </div>

        {/* Analysis Box */}
        <div className="bg-white rounded-2xl shadow-xl shadow-slate-200/50 border border-slate-100 overflow-hidden transition-all hover:shadow-2xl hover:shadow-slate-200/60">
          <div className="p-6">
            <textarea
              className="w-full h-40 p-4 text-lg border border-slate-200 rounded-xl focus:ring-4 focus:ring-blue-100 focus:border-blue-500 outline-none transition-all resize-none bg-slate-50/50"
              placeholder={language === 'en' ? "Paste suspicious message or URL here..." : "संदिग्ध संदेश या URL यहाँ पेस्ट करें..."}
              value={input}
              onChange={(e) => setInput(e.target.value)}
            />
            
            <button
              onClick={analyzeThreat}
              disabled={loading || !input.trim()}
              className={`w-full mt-4 py-4 rounded-xl font-bold text-white flex items-center justify-center gap-2 transition-all ${
                loading || !input.trim() 
                ? 'bg-slate-300 cursor-not-allowed' 
                : 'bg-blue-600 hover:bg-blue-700 active:scale-[0.98]'
              }`}
            >
              {loading ? (
                <div className="flex items-center gap-3">
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>{language === 'en' ? 'Analyzing...' : 'विश्लेषण कर रहा है...'}</span>
                </div>
              ) : (
                <>
                  <Search className="w-5 h-5" />
                  <span>{language === 'en' ? 'Check for Risk' : 'खतरे की जाँच करें'}</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Error State */}
        {error && (
          <div className="mt-6 p-4 bg-red-50 border border-red-100 rounded-xl text-red-600 flex items-center gap-3 animate-in fade-in slide-in-from-top-4">
            <AlertTriangle className="w-5 h-5 flex-shrink-0" />
            <p className="font-medium">{error}</p>
          </div>
        )}

        {/* Results Section */}
        {result && (
          <div className="mt-10 space-y-6 animate-in fade-in slide-in-from-bottom-8 duration-500">
            {/* Risk Badge */}
            <div className={`p-8 rounded-2xl border-2 flex flex-col md:flex-row items-center gap-6 ${getRiskColor(result.riskLevel)}`}>
              <div className="p-4 rounded-full bg-white/50 backdrop-blur-sm shadow-sm">
                {getRiskIcon(result.riskLevel)}
              </div>
              <div className="text-center md:text-left">
                <div className="text-sm font-bold uppercase tracking-wider opacity-70 mb-1">
                  {language === 'en' ? 'Security Status' : 'सुरक्षा स्थिति'}
                </div>
                <h3 className="text-3xl font-black mb-2">
                  {result.riskLevel === 'Safe' && (language === 'en' ? 'SAFE' : 'सुरक्षित')}
                  {result.riskLevel === 'Suspicious' && (language === 'en' ? 'SUSPICIOUS' : 'संदिग्ध')}
                  {result.riskLevel === 'Dangerous' && (language === 'en' ? 'DANGEROUS' : 'खतरनाक')}
                </h3>
                <p className="text-lg font-medium opacity-90 leading-relaxed">
                  {language === 'en' ? result.explanation_en : result.explanation_hi}
                </p>
              </div>
            </div>

            {/* Detailed Cards */}
            <div className="grid md:grid-cols-2 gap-6">
              {/* Safety Tips */}
              <div className="bg-white p-6 rounded-2xl border border-slate-200">
                <div className="flex items-center gap-2 mb-4 text-blue-600">
                  <Lock className="w-5 h-5" />
                  <h4 className="font-bold text-slate-800">
                    {language === 'en' ? 'Safety Checklist' : 'सुरक्षा चेकलिस्ट'}
                  </h4>
                </div>
                <ul className="space-y-3">
                  {(language === 'en' ? result.tips_en : result.tips_hi).map((tip, idx) => (
                    <li key={idx} className="flex items-start gap-3 text-slate-600 text-sm">
                      <div className="mt-1 bg-blue-50 text-blue-600 rounded-full p-0.5">
                        <ChevronRight className="w-3 h-3" />
                      </div>
                      {tip}
                    </li>
                  ))}
                </ul>
              </div>

              {/* Red Flags */}
              <div className="bg-white p-6 rounded-2xl border border-slate-200">
                <div className="flex items-center gap-2 mb-4 text-orange-500">
                  <Info className="w-5 h-5" />
                  <h4 className="font-bold text-slate-800">
                    {language === 'en' ? 'Threat Indicators' : 'खतरे के संकेत'}
                  </h4>
                </div>
                <div className="flex flex-wrap gap-2">
                  {result.indicators.map((tag, idx) => (
                    <span key={idx} className="px-3 py-1 bg-slate-100 text-slate-700 rounded-lg text-xs font-semibold">
                      {tag}
                    </span>
                  ))}
                </div>
                <div className="mt-6 pt-4 border-t border-slate-100">
                   <div className="flex justify-between items-center text-xs text-slate-400">
                    <span>Threat Score:</span>
                    <span className="font-mono font-bold text-slate-600">{result.score}/100</span>
                   </div>
                   <div className="w-full bg-slate-100 h-1.5 rounded-full mt-2 overflow-hidden">
                    <div 
                      className={`h-full transition-all duration-1000 ${result.riskLevel === 'Dangerous' ? 'bg-red-500' : 'bg-blue-500'}`}
                      style={{ width: `${result.score}%` }}
                    />
                   </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Educational Section */}
        {!result && !loading && (
          <div className="mt-12 grid md:grid-cols-3 gap-4 opacity-70">
            <div className="bg-white/50 p-4 rounded-xl border border-dashed border-slate-300">
              <h5 className="font-bold text-xs mb-2 uppercase text-slate-500">Phishing</h5>
              <p className="text-xs">Fake websites trying to steal your bank login or credit card.</p>
            </div>
            <div className="bg-white/50 p-4 rounded-xl border border-dashed border-slate-300">
              <h5 className="font-bold text-xs mb-2 uppercase text-slate-500">Vishing</h5>
              <p className="text-xs">Fraudulent phone calls claiming to be from your bank or govt.</p>
            </div>
            <div className="bg-white/50 p-4 rounded-xl border border-dashed border-slate-300">
              <h5 className="font-bold text-xs mb-2 uppercase text-slate-500">Smishing</h5>
              <p className="text-xs">SMS scams with "Urgent" links about accounts being blocked.</p>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="mt-auto pt-20 text-center text-slate-400 text-sm">
        <p>© 2025 Tech4Impact • CyberRakshak AI Project</p>
        <div className="flex justify-center gap-4 mt-2">
          <a href="#" className="hover:text-blue-500 flex items-center gap-1">Docs <ExternalLink className="w-3 h-3"/></a>
          <a href="#" className="hover:text-blue-500 flex items-center gap-1">Report Fraud <ExternalLink className="w-3 h-3"/></a>
        </div>
      </footer>
    </div>
  );
};

export default App;

