document.addEventListener('DOMContentLoaded', () => {

  // Get all "navbar-burger" elements
  const $navbarBurgers = Array.prototype.slice.call(document.querySelectorAll('.navbar-burger'), 0);

  // Add a click event on each of them
  $navbarBurgers.forEach( el => {
    el.addEventListener('click', () => {

      // Get the target from the "data-target" attribute
      const target = el.dataset.target;
      const $target = document.getElementById(target);

      // Toggle the "is-active" class on both the "navbar-burger" and the "navbar-menu"
      el.classList.toggle('is-active');
      $target.classList.toggle('is-active');

    });
  });

  const $radioButtons = Array.prototype.slice.call(document.querySelectorAll('input[name="days"]'), 0);

  $radioButtons.forEach( el => {
    el.addEventListener('click', () => {
      $.ajax({
        url:window.location.href,
        method:"GET",
        data:{range:el.value},
        success:function(data)
        {
          $('#events_id').html(data);
          $('#events_id').append(data.events_range);
        }
      })
    });
  });

  var dropdown = document.querySelector('.dropdown');
  dropdown.addEventListener('click', function(event) {
    event.stopPropagation();
    dropdown.classList.toggle('is-active');
  });

});