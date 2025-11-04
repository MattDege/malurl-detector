// frontend/src/App.jsx
import React, {useState} from "react";

function App(){
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  async function submit(e){
    e.preventDefault();
    setLoading(true);
    setResult(null);
    try{
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({url}),
      });
      const data = await res.json();
      setResult(data);
    }catch(err){
      setResult({error: err.message});
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-6 max-w-2xl mx-auto">
      <h1 className="text-xl font-bold mb-4">MalURL Scanner</h1>
      <form onSubmit={submit} className="mb-4">
        <input className="border p-2 w-full" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com/..." />
        <button className="mt-2 bg-blue-600 text-white px-4 py-2" type="submit" disabled={loading}>{loading ? "Scanning…" : "Scan"}</button>
      </form>

      {result && result.error && <div className="text-red-600">{result.error}</div>}

      {result && !result.error && (
        <div className="bg-gray-50 p-4 rounded">
          <div><strong>URL:</strong> {result.url}</div>
          <div><strong>Rule score:</strong> {result.rule_score.toFixed(3)} ({result.rule_label ? "malicious":"benign"})</div>
          {result.ml_proba !== null && <div><strong>ML prob:</strong> {result.ml_proba}</div>}
          <h3 className="mt-2 font-semibold">Top contributions</h3>
          <ul>
            {Object.entries(result.explain.contributions).sort((a,b)=>Math.abs(b[1])-Math.abs(a[1])).slice(0,8).map(([k,v])=>(
              <li key={k}><code>{k}</code>: {v.toFixed(3)}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default App;
