async function updateAccountLink() {
  const accountLinks = document.querySelectorAll('a[href="auth.html"]');

  try {
    const response = await fetch('/api/me');
    const result = await response.json();
    if (result.user) {
      accountLinks.forEach((link) => {
        link.textContent = result.user.name;
        link.addEventListener('click', (event) => {
          const logoutButton = link.parentElement.querySelector('.logout-button');
          const settingsLink = link.parentElement.querySelector('.account-settings-link');
          if (logoutButton && settingsLink) {
            event.preventDefault();
            logoutButton.hidden = !logoutButton.hidden;
            settingsLink.hidden = !settingsLink.hidden;
          }
        });

        const settingsLink = document.createElement('a');
        settingsLink.className = 'account-settings-link';
        settingsLink.href = 'account-settings.html';
        settingsLink.textContent = 'Account settings';
        settingsLink.hidden = true;

        const logoutButton = document.createElement('button');
        logoutButton.className = 'logout-button';
        logoutButton.type = 'button';
        logoutButton.textContent = 'Log out';
        logoutButton.hidden = true;
        logoutButton.addEventListener('click', async () => {
          await fetch('/api/logout', { method: 'POST' });
          window.location.href = 'index.html';
        });
        link.parentElement.appendChild(settingsLink);
        link.parentElement.appendChild(logoutButton);
      });

      if (result.user.isAdmin) {
        const navigation = document.querySelector('nav ul');
        if (navigation && !navigation.querySelector('a[href="dashboard.html"]')) {
          const dashboardItem = document.createElement('li');
          const dashboardLink = document.createElement('a');
          dashboardLink.href = 'dashboard.html';
          dashboardLink.textContent = 'Dashboard';
          dashboardItem.appendChild(dashboardLink);
          navigation.appendChild(dashboardItem);
        }
      }
    }
  } catch {
    // The navigation keeps its Account label when the account server is offline.
  }
}

updateAccountLink();
