const params = new URLSearchParams(
    window.location.search
);

const originalUrl = params.get("url");

const urlBox = document.getElementById("url");

if (originalUrl) {
    urlBox.textContent = originalUrl;
} else {
    urlBox.textContent = "Original URL unavailable";
}

document
    .getElementById("backButton")
    .addEventListener("click", () => {
        history.back();
    });

document
    .getElementById("continueButton")
    .addEventListener("click", () => {
        if (originalUrl) {
            window.location.href = originalUrl;
        }
    });
