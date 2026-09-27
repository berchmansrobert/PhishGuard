const PHISHGUARD_API =
    "https://phishguard-39yz.onrender.com/check-url";

const checkedTabs = new Map();

async function checkUrl(url) {
    try {
        const response = await fetch(
            PHISHGUARD_API,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    url: url
                })
            }
        );

        if (!response.ok) {
            throw new Error(
                `PhishGuard API error: ${response.status}`
            );
        }

        return await response.json();

    } catch (error) {
        console.error(
            "PhishGuard error:",
            error
        );

        return {
            risk_level: "unknown",
            action: "ask_user",
            findings: [
                "PhishGuard server could not be reached"
            ]
        };
    }
}

function isWebUrl(url) {
    return (
        url.startsWith("http://") ||
        url.startsWith("https://")
    );
}

function isExtensionPage(url) {
    return (
        url.startsWith("chrome://") ||
        url.startsWith("edge://") ||
        url.startsWith("about:") ||
        url.startsWith("chrome-extension://")
    );
}

chrome.tabs.onUpdated.addListener(
    async (tabId, changeInfo, tab) => {

        if (changeInfo.status !== "loading") {
            return;
        }

        const url = tab.url;

        if (!url) {
            return;
        }

        if (isExtensionPage(url)) {
            return;
        }

        if (!isWebUrl(url)) {
            return;
        }

        const previousUrl =
            checkedTabs.get(tabId);

        if (previousUrl === url) {
            return;
        }

        checkedTabs.set(tabId, url);

        const result = await checkUrl(url);

        console.log(
            "PhishGuard result:",
            result
        );

        if (result.action === "block") {

            chrome.tabs.update(
                tabId,
                {
                    url:
                        chrome.runtime.getURL(
                            "blocked.html"
                        )
                }
            );

            return;
        }

        if (result.action === "ask_user") {

            const warningUrl =
                chrome.runtime.getURL(
                    "warning.html"
                ) +
                "?url=" +
                encodeURIComponent(url);

            chrome.tabs.update(
                tabId,
                {
                    url: warningUrl
                }
            );
        }
    }
);

chrome.tabs.onRemoved.addListener(
    (tabId) => {
        checkedTabs.delete(tabId);
    }
);
