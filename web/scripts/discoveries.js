let credentialsFontSize = 12;
let lootFontSize = 14;

if (/Mobi|Android/i.test(navigator.userAgent)) {
    credentialsFontSize = 7;
    lootFontSize = 7;
}

function fetchCredentials() {
    fetch('/list_credentials')
        .then(response => response.text())
        .then(data => {
            document.getElementById('credentials-table').innerHTML = data;
            document.getElementById('credentials-table').style.fontSize = `${credentialsFontSize}px`;
        })
        .catch(error => {
            console.error('Error loading credentials:', error);
        });
}

function fetchLoot() {
    fetch('/list_files')
        .then(response => response.json())
        .then(data => {
            document.getElementById('file-list').innerHTML = generateFileListHTML(data, '/', 0);
            document.getElementById('file-list').style.fontSize = `${lootFontSize}px`;
        })
        .catch(error => {
            console.error('Error loading loot:', error);
        });
}

function generateFileListHTML(files, path, indent) {
    let html = '<ul>';
    files.forEach(file => {
        if (file.is_directory) {
            const icon = path === '/' ? 'web/images/mainfolder.png' : 'web/images/subfolder.png';
            html += `
                <li style="margin-left: ${indent * 5}px;">
                    <img src="${icon}" alt="Folder Icon" style="height: 20px;">
                    <strong>${file.name}</strong>
                    <ul>
                        ${generateFileListHTML(file.children || [], `${path}/${file.name}`, indent + 1)}
                    </ul>
                </li>`;
        } else {
            const icon = 'web/images/file.png';
            html += `
                <li style="margin-left: ${indent * 5}px;">
                    <img src="${icon}" alt="File Icon" style="height: 20px;">
                    <a href="/download_file?path=${encodeURIComponent(file.path)}">${file.name}</a>
                </li>`;
        }
    });
    html += '</ul>';
    return html;
}

function adjustCredentialsFontSize(change) {
    credentialsFontSize += change;
    document.getElementById('credentials-table').style.fontSize = `${credentialsFontSize}px`;
}

function adjustLootFontSize(change) {
    lootFontSize += change;
    document.getElementById('file-list').style.fontSize = `${lootFontSize}px`;
}

function toggleDiscoveriesToolbar() {
    const mainToolbar = document.querySelector('.toolbar');
    const toggleButton = document.getElementById('toggle-toolbar');
    const toggleIcon = document.getElementById('toggle-icon');

    if (mainToolbar.classList.contains('hidden')) {
        mainToolbar.classList.remove('hidden');
        toggleIcon.src = '/web/images/hide.png';
        toggleButton.setAttribute('data-open', 'false');
    } else {
        mainToolbar.classList.add('hidden');
        toggleIcon.src = '/web/images/reveal.png';
        toggleButton.setAttribute('data-open', 'true');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    fetchCredentials();
    fetchLoot();
    setInterval(fetchCredentials, 10000);
    setInterval(fetchLoot, 10000);
});
