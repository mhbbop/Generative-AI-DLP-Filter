document.addEventListener('DOMContentLoaded', () => {
    const togglePii = document.getElementById('toggle-pii');
    const toggleCredentials = document.getElementById('toggle-credentials');
    const toggleFinancial = document.getElementById('toggle-financial');
    const toggleAutoMask = document.getElementById('toggle-automask'); // [BARU]

    chrome.storage.local.get(['dlpSettings'], (result) => {
        const settings = result.dlpSettings || { pii: true, credentials: true, financial: true, autoMask: false };
        if (togglePii) togglePii.checked = settings.pii;
        if (toggleCredentials) toggleCredentials.checked = settings.credentials;
        if (toggleFinancial) toggleFinancial.checked = settings.financial;
        if (toggleAutoMask) toggleAutoMask.checked = settings.autoMask; // [BARU]
    });

    function saveSettings() {
        const newSettings = {
            pii: togglePii.checked,
            credentials: toggleCredentials.checked,
            financial: toggleFinancial.checked,
            autoMask: toggleAutoMask ? toggleAutoMask.checked : false // [BARU]
        };
        chrome.storage.local.set({ dlpSettings: newSettings }, () => {
            document.body.style.opacity = '0.7';
            setTimeout(() => document.body.style.opacity = '1', 150);
        });
    }

    if (togglePii) togglePii.addEventListener('change', saveSettings);
    if (toggleCredentials) toggleCredentials.addEventListener('change', saveSettings);
    if (toggleFinancial) toggleFinancial.addEventListener('change', saveSettings);
    if (toggleAutoMask) toggleAutoMask.addEventListener('change', saveSettings); // [BARU]
});