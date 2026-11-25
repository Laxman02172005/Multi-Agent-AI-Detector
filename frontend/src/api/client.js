import axios from "axios";

const api = axios.create({ baseURL: "/api", withCredentials: true });

// Health & auth state
export const getHealth = () => api.get("/health").then((r) => r.data);

// File & raw email previews (Stage 2 before scanning)
export const previewFile = (file) => {
  const fd = new FormData();
  fd.append("file", file);
  return api.post("/preview/file", fd).then((r) => r.data);
};

export const previewRaw = (text) =>
  api.post("/preview/raw", { text }).then((r) => r.data);

// Scans (Stage 3 & Stage 4 Threshold Lab re-evaluation)
export const scanFile = (file, abstainLow = 0.35, abstainHigh = 0.65) => {
  const fd = new FormData();
  fd.append("file", file);
  return api
    .post(`/scan/file?abstain_low=${abstainLow}&abstain_high=${abstainHigh}`, fd)
    .then((r) => r.data);
};

export const scanRaw = (text, abstainLow = 0.35, abstainHigh = 0.65) =>
  api.post("/scan/raw", { text, abstain_low: abstainLow, abstain_high: abstainHigh }).then((r) => r.data);

// Built-in demo corpus
export const listSamples = () => api.get("/samples").then((r) => r.data);
export const previewSample = (id) => api.get(`/samples/${id}/preview`).then((r) => r.data);
export const scanSample = (id, abstainLow = 0.35, abstainHigh = 0.65) =>
  api.post(`/scan/sample/${id}`, { abstain_low: abstainLow, abstain_high: abstainHigh }).then((r) => r.data);

// Gmail OAuth 2.0
export const startGmailAuth = () => {
  window.location.href = "/api/auth/google";
};
export const logoutGmail = () => api.post("/auth/logout").then((r) => r.data);

// Gmail inbox & message operations
export const listGmailMessages = (maxResults = 20) =>
  api.get(`/gmail/messages?max_results=${maxResults}`).then((r) => r.data);
export const previewGmailMessage = (msgId) =>
  api.get(`/gmail/messages/${msgId}`).then((r) => r.data);
export const scanGmailMessage = (msgId, abstainLow = 0.35, abstainHigh = 0.65) =>
  api.post(`/gmail/scan/${msgId}`, { abstain_low: abstainLow, abstain_high: abstainHigh }).then((r) => r.data);
