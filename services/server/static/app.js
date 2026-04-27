document.addEventListener('DOMContentLoaded', () => {
  const header = document.querySelector('.app-header');
  const navToggle = document.querySelector('[data-nav-toggle]');

  if (header && navToggle) {
    navToggle.addEventListener('click', () => {
      const isOpen = header.classList.toggle('is-open');
      navToggle.setAttribute('aria-expanded', String(isOpen));
    });
  }

  document.addEventListener('click', (event) => {
    const dismissButton = event.target.closest('[data-dismiss]');
    if (!dismissButton) {
      return;
    }

    const message = document.getElementById(dismissButton.dataset.dismiss);
    if (message) {
      message.remove();
    }
  });

  document.addEventListener('click', async (event) => {
    const rangeLink = event.target.closest('[data-range-link]');
    const dataRegion = document.getElementById('events_id');

    if (!rangeLink || !dataRegion) {
      return;
    }

    event.preventDefault();
    dataRegion.classList.add('is-loading');

    const fragmentUrl = new URL(rangeLink.href, window.location.origin);
    fragmentUrl.searchParams.set('partial', '1');

    try {
      const response = await fetch(fragmentUrl.toString(), {
        headers: {
          'X-Requested-With': 'XMLHttpRequest'
        }
      });

      if (!response.ok) {
        throw new Error(`Unexpected response: ${response.status}`);
      }

      dataRegion.innerHTML = await response.text();
      window.history.pushState({}, '', rangeLink.href);
      updateRangeState(rangeLink.dataset.rangeValue);
    } catch (error) {
      window.location.href = rangeLink.href;
    } finally {
      dataRegion.classList.remove('is-loading');
    }
  });
});

function updateRangeState(activeValue) {
  document.querySelectorAll('[data-range-link]').forEach((link) => {
    const isActive = link.dataset.rangeValue === activeValue;
    link.classList.toggle('is-active', isActive);
    link.setAttribute('aria-current', String(isActive));
  });
}
