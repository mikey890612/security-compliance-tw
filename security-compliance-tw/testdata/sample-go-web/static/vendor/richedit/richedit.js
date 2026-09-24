/*!
 * richedit v1.4.2 — lightweight rich text editor
 * (c) 2024 richedit contributors — MIT License
 */
(function (global) {
  'use strict';

  function defaultUploader(settings) {
    return function (blob, filename) {
      return new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', settings.uploadUrl);
        xhr.withCredentials = !!settings.credentials;
        Object.keys(settings.headers || {}).forEach(function (name) {
          xhr.setRequestHeader(name, settings.headers[name]);
        });
        xhr.onload = function () {
          if (xhr.status < 200 || xhr.status >= 300) {
            reject('HTTP Error: ' + xhr.status + ' ' + xhr.responseText);
            return;
          }
          resolve(JSON.parse(xhr.responseText).id);
        };
        xhr.onerror = function () {
          reject('Image upload failed due to a XHR Transport error. Code: ' + xhr.status);
        };
        var form = new FormData();
        form.append('file', blob, filename);
        xhr.send(form);
      });
    };
  }

  function Editor(el, settings) {
    this.el = el;
    this.settings = settings;
    this.upload = settings.uploader || defaultUploader(settings);
  }

  Editor.prototype.notify = function (message) {
    global.alert(message);
  };

  Editor.prototype.insertImage = function (file) {
    var self = this;
    return self.upload(file, file.name).then(function (id) {
      self.el.value += '\n[image:' + id + ']';
    }).catch(function (err) {
      self.notify(err);
    });
  };

  global.RichEdit = {
    create: function (el, settings) {
      return new Editor(el, settings);
    }
  };
})(window);
