import { useState, useEffect } from "react";
import NavBar from "./components/NavBar";
import CyberBackground from "./components/CyberBackground";
import ScanOverlay from "./components/ScanOverlay";
import EntryScreen from "./components/stages/EntryScreen";
import PreviewScreen from "./components/stages/PreviewScreen";
import VerdictScreen from "./components/stages/VerdictScreen";
import ForensicStepper from "./components/stages/ForensicStepper";
import {
  getHealth,
  scanFile,
  scanRaw,
  scanSample,
  scanGmailMessage,
} from "./api/client";

/*
  Progressive 4-stage flow:
    Stage 1 ("entry")    → EntryScreen (Gmail / File Upload / Demo Samples)
    Stage 2 ("preview")  → PreviewScreen (Inbox + Full Email Preview before scanning)
    Stage   ("scanning") → ScanOverlay (Radar animation)
    Stage 3 ("verdict")  → VerdictScreen (Clean prediction score & verdict only)
    Stage 4 ("forensic") → ForensicStepper (1: Agents -> 2: Drivers -> 3: Evidence)
*/

async function executeScanBySource(source, abstainLow = 0.35, abstainHigh = 0.65) {
  if (!source) throw new Error("No email source selected.");
  if (source.type === "gmail") return scanGmailMessage(source.id, abstainLow, abstainHigh);
  if (source.type === "sample") return scanSample(source.id, abstainLow, abstainHigh);
  if (source.type === "file") return scanFile(source.file, abstainLow, abstainHigh);
  if (source.type === "raw") return scanRaw(source.text, abstainLow, abstainHigh);
  throw new Error(`Unsupported source type: ${source.type}`);
}

export default function App() {
  const [stage, setStage] = useState("entry");
  const [previewMode, setPreviewMode] = useState("file"); // "gmail" | "demo" | "file"
  const [health, setHealth] = useState(null);
  const [gmailConnected, setGmailConnected] = useState(false);
  const [oauthError, setOauthError] = useState("");

  const [previewData, setPreviewData] = useState(null);
  const [scanSource, setScanSource] = useState(null);
  const [report, setReport] = useState(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const justConnected = params.get("gmail") === "connected";
    const authErr = params.get("gmail_error");

    if (justConnected || authErr) {
      window.history.replaceState({}, "", window.location.pathname);
    }
    if (authErr) {
      setOauthError(`Gmail sign-in error: ${authErr}`);
    }
    if (justConnected) {
      setGmailConnected(true);
      setPreviewMode("gmail");
      setStage("preview");
    }

    getHealth()
      .then((h) => {
        setHealth(h);
        if (h?.gmail_connected) {
          setGmailConnected(true);
        }
      })
      .catch(() => setHealth({ status: "offline" }));
  }, []);

  const handleOpenGmailInbox = () => {
    setPreviewData(null);
    setScanSource(null);
    setPreviewMode("gmail");
    setStage("preview");
  };

  const handleOpenDemoCorpus = () => {
    setPreviewData(null);
    setScanSource(null);
    setPreviewMode("demo");
    setStage("preview");
  };

  const handleFileOrPastePreviewReady = (previewObj, sourceObj) => {
    setPreviewData(previewObj);
    setScanSource(sourceObj);
    setPreviewMode("file");
    setStage("preview");
  };

  const handleStartScan = async (sourceObj, previewObj) => {
    setScanSource(sourceObj);
    setPreviewData(previewObj);
    setStage("scanning");

    const minDelay = new Promise((res) => setTimeout(res, 750));
    try {
      const [result] = await Promise.all([executeScanBySource(sourceObj), minDelay]);
      setReport(result);
    } catch (err) {
      await minDelay;
      setReport({ _error: err?.response?.data?.detail || err.message || "Scan failed." });
    }
    setStage("verdict");
  };

  const resetToEntry = () => {
    setStage("entry");
    setPreviewData(null);
    setScanSource(null);
    setReport(null);
  };

  return (
    <div className="min-h-screen relative flex flex-col" style={{ background: "#050811" }}>
      <CyberBackground />
      <NavBar health={health} gmailConnected={gmailConnected} onBrandClick={resetToEntry} />

      <main className="relative z-10 flex-1 flex flex-col items-center px-4 py-8">
        {stage === "entry" && (
          <EntryScreen
            health={health}
            gmailConnected={gmailConnected}
            oauthError={oauthError}
            onOpenGmailInbox={handleOpenGmailInbox}
            onOpenDemoCorpus={handleOpenDemoCorpus}
            onPreviewReady={handleFileOrPastePreviewReady}
          />
        )}

        {stage === "preview" && (
          <PreviewScreen
            mode={previewMode}
            initialPreview={previewData}
            initialSource={scanSource}
            onStartScan={handleStartScan}
            onBack={resetToEntry}
            onGmailLoggedOut={() => setGmailConnected(false)}
          />
        )}

        {stage === "scanning" && <ScanOverlay />}

        {stage === "verdict" && (
          <VerdictScreen
            report={report}
            preview={previewData}
            onInspectForensics={() => setStage("forensic")}
            onBackToPreview={() => setStage("preview")}
            onScanAnother={resetToEntry}
          />
        )}

        {stage === "forensic" && (
          <ForensicStepper
            report={report}
            onBackToVerdict={() => setStage("verdict")}
            onScanAnother={resetToEntry}
          />
        )}
      </main>
    </div>
  );
}
