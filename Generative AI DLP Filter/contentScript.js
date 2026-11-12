// ==========================================
// 1. ATURAN REGEX
// ==========================================
const RULES = {
    pii: [
        { name: "NIK", pattern:/\b(?:1[1-9]|21|[37][1-6]|5[1-3]|6[1-5]|8[12]|9[1-6])\d{4}(?:[04][1-9]|[1256][0-9]|[37][01])(?:0[1-9]|1[0-2])\d{6}\b/g, mask: "[NIK_DISAMARKAN]" },
        { name: "NPWP", pattern: /\b[1-9]\d{1}[\.\-]\d{3}[\.\-]\d{3}[\.\-]\d{1}[\.\-]\d{3}[\.\-]\d{3}\b/g, mask: "[NPWP_DISAMARKAN]" },
        { name: "Telepon", pattern: /(?:\+62|62|0)8[1-9][0-9]{1,2}[ \-]?[0-9]{3,4}[ \-]?[0-9]{3,4}\b/g, mask: "[TELEPON_DISAMARKAN]" },
        { name: "Paspor", pattern: /\b[A-CEX][0-9]{7}\b/g, mask: "[PASPOR_DISAMARKAN]" },
        { name: "STNK", pattern: /\b(?:B|D|E|F|T|Z|A|G|H|K|R|AA|AB|AD|AE|AG|S|W|L|M|N|P|DK|DR|EA|EB|ED|KB|DA|KT|KS|KU|DB|DL|DM|DN|DT|DD|DP|DW|PA|PB|DE|DG)\s\d{1,4}\s[A-Z]{1,3}\b/gi, mask: "[STNK_DISAMARKAN]" },
        { name: "Email", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, mask: "[EMAIL_DISAMARKAN]" },
        { name: "Alamat (Jalan)", pattern: /\b(?:Jl\.?|Jalan)\s+[A-Za-z0-9\s.-]{3,30}(?:\bNo\.?\s*\d+[A-Za-z]?\b)?/gi, mask: "[ALAMAT_DISAMARKAN]" },
        { name: "Alamat (RT/RW)", pattern: /\bRT\.?\s*0?\d{1,3}\s*[\/-]\s*RW\.?\s*0?\d{1,3}\b/gi, mask: "[RT/RW_DISAMARKAN]" }
    ],
    credentials: [
        { name: "OpenAI Key", pattern: /\bsk-[a-zA-Z0-9_\-]{32,}\b/g, mask: "[OPEN_AI_DISAMARKAN]" },
        { name: "GitHub Token", pattern: /\bgh[pasu]_[a-zA-Z0-9]{36}\b/g, mask: "[GITHUB_TOKEN_DISAMARKAN]" },
        { name: "Google Cloud Key", pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g, mask: "[GCP_KEY_DISAMARKAN]" },
        { name: "Slack Token", pattern: /\bxox[baprs]-[0-9]{10,13}-[a-zA-Z0-9]*\b/g, mask: "[SLACK_DISAMARKAN]" },
        { name: "API Key Umum", pattern: /(?:key|api|token|secret|password)[-_ ]*[:=][-_ ]*['"]?[a-zA-Z0-9\-_]{20,}['"]?/gi, mask: "[API_KEY_DISAMARKAN]" },
        { name: "AWS Access Key", pattern: /\bAKIA[0-9A-Z]{16}\b/g, mask: "[AWS_KEY_DISAMARKAN]" },
        { name: "Private Key", pattern: /-----BEGIN[\w\s]+PRIVATE KEY-----[\s\S]*?-----END[\w\s]+PRIVATE KEY-----/g, mask: "[PRIVATE_KEY_DISAMARKAN]" },
        { name: "Database JDBC", pattern: /jdbc:(?:mysql|postgresql|oracle|sqlserver):\/\/[A-Za-z0-9.-]+:[0-9]+\/[A-Za-z0-9_]+/gi, mask: "[DB_JDBC_DISAMARKAN]" }
    ],
    financial: [
        { name: "Kartu Kredit", pattern: /\b(?:4\d{3}|5[1-5]\d{2}|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}\b/g, mask: "[KARTU_KREDIT_DISAMARKAN]" },
        { name: "Rekening Bank", pattern: /\b(?:rek(?:ening)?|no(?:mor)?[\s\.\-]?rek(?:ening)?|bca|mandiri|bni|bri|bsi|cimb(?:[\s\.\-]?niaga)?|btn|mega|danamon|permata|jago|jenius|sea[\s\.\-]?bank)\b[\s:;=>\-]{1,5}(?:\d[\s\-]?){9,15}\d\b/gi, mask: "[REKENING_DISAMARKAN]" },
        { name: "IBAN", pattern: /\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b/g, mask: "[IBAN_DISAMARKAN]" },
        { name: "SWIFT/BIC", pattern: /\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g, mask: "[SWIFT/BIC_DISAMARKAN]" }
    ]
};

// ==========================================
// 2. PENGATURAN STATE
// ==========================================
let activeSettings = { pii: true, credentials: true, financial: true, autoMask: false };

chrome.storage.local.get(['dlpSettings'], (result) => {
    if (result.dlpSettings) activeSettings = result.dlpSettings;
});
chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local' && changes.dlpSettings) {
        activeSettings = changes.dlpSettings.newValue;
        updateVisualIndicator();
    }
});

// ==========================================
// 3. MESIN PENCARI & MASKING
// ==========================================
function getActiveChatInput() {
    const selectors = ['#prompt-textarea', 'div[contenteditable="true"].ProseMirror', 'rich-textarea', 'textarea'].join(',');
    for (let el of document.querySelectorAll(selectors)) {
        if (el.getBoundingClientRect().width > 0) return { element: el, text: el.innerText || el.value || "" };
    }
    return { element: null, text: "" };
}

function scanTextForSensitiveData(text) {
    if (!text || text.trim() === "") return null;
    for (const [category, isActive] of Object.entries(activeSettings)) {
        if (!isActive || category === 'autoMask') continue;
        for (const rule of RULES[category]) {
            rule.pattern.lastIndex = 0; 
            const match = rule.pattern.exec(text);
            if (match) return { message: rule.name, matchText: match[0] }; 
        }
    }
    return null;
}

function getMaskedText(text) {
    let maskedText = text;
    for (const [category, isActive] of Object.entries(activeSettings)) {
        if (!isActive || category === 'autoMask') continue;
        for (const rule of RULES[category]) {
            rule.pattern.lastIndex = 0;
            maskedText = maskedText.replace(rule.pattern, rule.mask);
        }
    }
    return maskedText;
}

function applyMaskToActiveInput() {
    const { element, text } = getActiveChatInput();
    if (!element || !text) return;

    const safeText = getMaskedText(text);
    element.focus();
    
    if (element.tagName === 'TEXTAREA') {
        const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
        nativeSetter.call(element, safeText);
        element.dispatchEvent(new Event('input', { bubbles: true }));
    } else {
        document.execCommand('selectAll', false, null);
        document.execCommand('insertText', false, safeText);
    }
    
    const toast = document.querySelector('.dlp-toast-container');
    if (toast) toast.remove();
    updateVisualIndicator();
}

// ==========================================
// 4. UI: NOTIFIKASI & INDIKATOR
// ==========================================
const SEND_BTN_SELECTORS = '[data-testid="send-button"], [aria-label*="Send" i], [aria-label*="Kirim" i], button.send-button, button[mattooltip*="Send" i], button.mb-1.me-1, .send-button-container button';

function showDLPToast(violationData) {
    const oldToast = document.querySelector('.dlp-toast-container');
    if (oldToast) oldToast.remove();

    const toast = document.createElement('div');
    toast.className = 'dlp-toast-container';
    toast.style.cssText = "position:fixed; top:20px; left:50%; transform:translateX(-50%); z-index:2147483647; width:450px; background:#fff; border-left:6px solid #e74c3c; box-shadow:0 4px 16px rgba(0,0,0,0.25); border-radius:8px; padding:16px; display:flex; flex-direction:column; gap:12px; font-family:sans-serif; transition:opacity 0.3s;";
    
    toast.innerHTML = `
        <div style="display:flex; gap:12px; align-items:flex-start;">
            <div style="font-size:22px;">🛡️</div>
            <div style="flex-grow:1;">
                <div style="font-weight:bold; color:#c0392b; margin-bottom:4px; font-size:15px;">DLP Intercepted: ${violationData.message}</div>
                <div style="color:#444; font-size:13px; line-height:1.5;">
                    Pengiriman ditahan! Ditemukan: <br/>
                    <span style="background-color:#ffe0e0; color:#c0392b; padding:2px 6px; border-radius:4px; font-weight:bold; font-family:monospace; display:inline-block; margin-top:4px;">${violationData.matchText}</span>
                </div>
            </div>
        </div>
        <div style="display:flex; justify-content:flex-end; border-top:1px solid #eee; padding-top:10px;">
            <button id="dlp-mask-btn" style="background:#e74c3c; color:white; border:none; padding:8px 16px; border-radius:4px; cursor:pointer; font-weight:bold; font-size:12px; transition:0.2s;">
                ✨ Samarkan Data (Masking)
            </button>
        </div>
    `;
    
    document.body.appendChild(toast);
    document.getElementById('dlp-mask-btn')?.addEventListener('click', applyMaskToActiveInput);

    setTimeout(() => { 
        if(document.body.contains(toast)) {
            toast.style.opacity = '0'; 
            setTimeout(() => toast.remove(), 300); 
        }
    }, 8000);
}

function updateVisualIndicator() {
    const { text } = getActiveChatInput();
    const violationData = scanTextForSensitiveData(text);
    
    document.querySelectorAll(SEND_BTN_SELECTORS).forEach(btn => {
        if (violationData) {
            btn.style.boxShadow = "0 0 0 2px #b60a0a";
            btn.style.backgroundColor = "#b60a0a";
        } else {
            btn.style.boxShadow = "";
            btn.style.backgroundColor = "";
        }
    });
}

// ==========================================
// 5. INTERCEPTOR (SATPAM JAVASCRIPT)
// ==========================================
function interceptAndBlock(event) {
    let isSendAction = false;
    if (event.type === 'keydown' || event.type === 'keyup') {
        if (event.key === 'Enter' && !event.shiftKey) isSendAction = true;
    } else {
        if (event.target.closest(SEND_BTN_SELECTORS)) isSendAction = true;
    }

    if (isSendAction) {
        const { element, text } = getActiveChatInput();
        const violationData = scanTextForSensitiveData(text);

        if (violationData) {
            event.preventDefault();             
            event.stopPropagation();            
            event.stopImmediatePropagation();   

            if (activeSettings.autoMask) {
                applyMaskToActiveInput();
                const oldToast = document.querySelector('.dlp-toast-container');
                if(!oldToast) {
                   showDLPToast({ message: "Auto-Masking Aktif", matchText: "Data telah disamarkan secara otomatis." });
                }
            } else {
                if (event.type === 'keydown' || event.type === 'mousedown' || event.type === 'pointerdown') {
                     showDLPToast(violationData);
                     if (element) {
                         element.style.outline = "2px solid #e74c3c";
                         setTimeout(() => element.style.outline = "", 2000);
                     }
                }
            }
        }
    }
}

['keydown', 'keyup', 'click', 'mousedown', 'pointerdown', 'submit'].forEach(evtType => {
    window.addEventListener(evtType, interceptAndBlock, true);
});
document.addEventListener('input', updateVisualIndicator, true);
document.addEventListener('keyup', updateVisualIndicator, true);