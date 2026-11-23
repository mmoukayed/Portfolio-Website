// Add a value here when Mohamad is ready to publish a contact destination.
// Leave blank to keep the visible, non-clickable setup prompt in the footer.
const profileLinks = {
  email: "",
  github: "",
  linkedin: ""
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

// Opening fade and one-time scroll reveals.
const revealTargets = $$('[data-reveal]');
const revealObserver = new IntersectionObserver((entries, observer) => {
  entries.forEach((entry) => {
    if (entry.isIntersecting) {
      entry.target.classList.add('is-visible');
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.12, rootMargin: '0px 0px -4% 0px' });
revealTargets.forEach((target) => revealObserver.observe(target));
document.body.classList.add('motion-ready');
requestAnimationFrame(() => {
  document.documentElement.classList.remove('page-loading');
  document.documentElement.classList.add('page-loaded');
});

// Mobile navigation.
const navToggle = $('#navToggle');
const siteNav = $('#siteNav');
function setNavOpen(open) {
  navToggle.setAttribute('aria-expanded', String(open));
  navToggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
  siteNav.classList.toggle('open', open);
}
navToggle.addEventListener('click', () => setNavOpen(navToggle.getAttribute('aria-expanded') !== 'true'));
$$('.site-nav a').forEach((link) => link.addEventListener('click', () => setNavOpen(false)));
window.addEventListener('resize', () => {
  if (window.innerWidth > 700) setNavOpen(false);
});

// Keep the header quiet at the top and defined after the first scroll.
const siteHeader = $('.site-header');
const updateHeader = () => siteHeader.classList.toggle('scrolled', window.scrollY > 8);
window.addEventListener('scroll', updateHeader, { passive: true });
updateHeader();

// Pointer-driven rotation for the technical robot illustration.
const robotStage = $('#robotStage');
const robotModel = $('#robotModel');
let robotDragging = false;
let pointerX = 0;
let pointerY = 0;
let modelRotateX = 9;
let modelRotateY = -12;
function renderRobotRotation() {
  robotModel.style.transform = `rotateX(${modelRotateX}deg) rotateY(${modelRotateY}deg)`;
}
robotStage.addEventListener('pointerdown', (event) => {
  if (event.target.closest('button')) return;
  robotDragging = true;
  pointerX = event.clientX;
  pointerY = event.clientY;
  robotStage.setPointerCapture(event.pointerId);
});
robotStage.addEventListener('pointermove', (event) => {
  if (!robotDragging) return;
  modelRotateY += (event.clientX - pointerX) * 0.42;
  modelRotateX -= (event.clientY - pointerY) * 0.3;
  modelRotateX = Math.max(-15, Math.min(30, modelRotateX));
  pointerX = event.clientX;
  pointerY = event.clientY;
  renderRobotRotation();
});
robotStage.addEventListener('pointerup', () => { robotDragging = false; });
robotStage.addEventListener('pointercancel', () => { robotDragging = false; });
$('#modelControl').addEventListener('click', () => {
  modelRotateY += 72;
  robotStage.classList.add('is-spinning');
  renderRobotRotation();
  window.setTimeout(() => robotStage.classList.remove('is-spinning'), 850);
});

// Guided tour: visitors can advance while seeing each destination on the page.
const tourStops = [
  { target: 'projects', title: 'Start with the work.', description: 'The autonomous sumo robot leads the featured builds, with technical notes for each project.' },
  { target: 'experiments', title: 'Then the lab notes.', description: 'These are smaller experiments and prototypes, clearly marked by their current status.' },
  { target: 'skills', title: 'The tools behind it.', description: 'Browse the technical toolkit by discipline, without arbitrary skill ratings.' },
  { target: 'achievements', title: 'Competition results.', description: 'MakeX and CSAW results sit alongside the other competition experience.' },
  { target: 'contact', title: 'Continue the conversation.', description: 'Contact destinations can be added in the profileLinks object in app.js.' }
];
const guidedTour = $('#guidedTour');
const tourTrigger = $('#tourTrigger');
const tourNext = $('#tourNext');
let tourIndex = 0;
let tourWasOpen = false;
function renderTourStop() {
  const stop = tourStops[tourIndex];
  $('#tourCount').textContent = `${String(tourIndex + 1).padStart(2, '0')} / ${String(tourStops.length).padStart(2, '0')}`;
  $('#tourTitle').textContent = stop.title;
  $('#tourDescription').textContent = stop.description;
  tourNext.innerHTML = tourIndex === tourStops.length - 1 ? 'Finish tour <span aria-hidden="true">✓</span>' : 'Next section <span aria-hidden="true">→</span>';
}
function openTour() {
  tourIndex = 0;
  renderTourStop();
  guidedTour.hidden = false;
  guidedTour.setAttribute('aria-hidden', 'false');
  tourWasOpen = true;
  document.getElementById(tourStops[tourIndex].target).scrollIntoView({ behavior: 'smooth', block: 'start' });
  tourNext.focus();
}
function closeTour(restoreFocus = true) {
  guidedTour.hidden = true;
  guidedTour.setAttribute('aria-hidden', 'true');
  if (restoreFocus && tourWasOpen) tourTrigger.focus();
  tourWasOpen = false;
}
tourTrigger.addEventListener('click', openTour);
$('#tourClose').addEventListener('click', () => closeTour());
$('#tourSkip').addEventListener('click', () => closeTour());
tourNext.addEventListener('click', () => {
  if (tourIndex === tourStops.length - 1) {
    closeTour();
    return;
  }
  tourIndex += 1;
  renderTourStop();
  document.getElementById(tourStops[tourIndex].target).scrollIntoView({ behavior: 'smooth', block: 'start' });
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    if (!guidedTour.hidden) closeTour();
    if (navToggle.getAttribute('aria-expanded') === 'true') setNavOpen(false);
  }
});

// Populate only contact links supplied by Mohamad. Missing details remain explicit prompts.
function validWebUrl(value) {
  try {
    const url = new URL(value);
    return ['https:', 'http:'].includes(url.protocol) ? url.href : '';
  } catch {
    return '';
  }
}
const contactLabels = {
  email: { prompt: 'Add email address in app.js', value: profileLinks.email, href: profileLinks.email ? `mailto:${profileLinks.email}` : '' },
  github: { prompt: 'Add profile URL in app.js', value: validWebUrl(profileLinks.github), href: validWebUrl(profileLinks.github) },
  linkedin: { prompt: 'Add profile URL in app.js', value: validWebUrl(profileLinks.linkedin), href: validWebUrl(profileLinks.linkedin) }
};
$$('[data-contact]').forEach((item) => {
  const entry = contactLabels[item.dataset.contact];
  if (!entry?.value || !entry.href) {
    const placeholder = $('.contact-value', item);
    placeholder.textContent = entry?.prompt ?? 'Add contact details in app.js';
    placeholder.classList.add('placeholder');
    return;
  }
  const anchor = document.createElement('a');
  anchor.href = entry.href;
  anchor.textContent = entry.value;
  if (entry.href.startsWith('https:')) {
    anchor.target = '_blank';
    anchor.rel = 'noopener noreferrer';
  }
  $('.contact-value', item).replaceWith(anchor);
});

$('#yearNow').textContent = new Date().getFullYear();
