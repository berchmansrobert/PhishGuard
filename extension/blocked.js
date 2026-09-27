const params = new URLSearchParams(
    window.location.search
);

const originalUrl = params.get("url");

const urlBox = document.getElementById("url");

if (originalUrl) {
    urlBox.textContent = originalUrl;
}

document
    .getElementById("backButton")
    .addEventListener("click", () => {
        history.back();
    });
