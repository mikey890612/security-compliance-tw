(function ($) {
  'use strict';

  function showNotice(message, level) {
    var box = $('#notice');
    box.removeClass('d-none alert-info alert-danger').addClass(level);
    box.find('span').text(message);
  }

  $('[data-copy]').on('click', function () {
    var source = $($(this).data('copy'));
    navigator.clipboard.writeText(source.val()).then(function () {
      showNotice('已複製', 'alert-info');
    }, function (err) {
      showNotice('複製失敗：' + err, 'alert-danger');
    });
  });

  var body = document.getElementById('body');
  if (body) {
    var editor = RichEdit.create(body, {
      uploadUrl: '/editor/images',
      credentials: true,
      headers: { 'X-CSRF-Token': $('meta[name="csrf-token"]').attr('content') }
    });
    $('#body-image').on('change', function () {
      if (this.files[0]) {
        editor.insertImage(this.files[0]);
      }
    });
  }
})(jQuery);
