window.appPrefix = document.location.pathname;

/**
 * Home view
 */
var home = {
  // Dom references
  uploadButton: document.getElementById('uploadButton'),
  scanButton: document.getElementById('scanButton'),
  searchButton: document.getElementById('searchButton'),
  fileSelector: document.getElementById('fileSelector'),
  selectedFileName: document.getElementById('selectedFileName'),
  tabsWrapper: document.getElementById('tabsWrapper'),
  fileTab: document.getElementById('fileTab'),
  urlTab: document.getElementById('urlTab'),
  searchTab: document.getElementById('searchTab'),
  terminalTab: document.getElementById('terminalTab'),
  urlInput: document.getElementById('urlInput'),
  searchInput: document.getElementById('searchInput'),

  file: undefined,
};

home.confirmUpload = function() {
  if (home.file) {
    home.setUploadButtonText('Uploading file<span id="wait"></span>');
    uploadButton.setAttribute('disabled', 1);
    var dots = window.setInterval(function() {
      var wait = document.getElementById("wait");
      if (wait.innerHTML.length > 3) {
        wait.innerHTML = "";
      }
      else {
        wait.innerHTML += ".";
      }
    }, 500);
    home.getUploadUrl(home.file, function(response) {
      request.postFile(response.data, home.file, function(response) {
        document.location.href =
          appPrefix + 'file-analysis/' + response.data.id;
        home.reset();
      });
    });
  }
}

home.fileChanged = function(e) {
  home.file = e.currentTarget.files[0];
  home.selectedFileName.innerHTML = home.file.name;
  home.setUploadButtonText('Confirm upload');
  home.uploadButton.addEventListener('click', home.confirmUpload);
}

home.getUploadUrl = function(file, callback) {
  request.get('https://www.virustotal.com/ui/files/upload_url', function(response) {
    callback(response);
  });
}

home.reset = function() {
  home.setUploadButtonText('Choose file');
  home.selectedFileName.innerHTML = '';
  home.file = undefined;
  home.uploadButton.removeEventListener('click', home.confirmUpload);
}

home.selecFile = function() {
  if (home.file) {
    return;
  }
  home.fileSelector.click();
}

home.setUploadButtonText = function(text) {
  home.uploadButton.innerHTML = text;
}

home.selectTab = function(e) {
  e.preventDefault();

  var tabs = home.tabsWrapper.children;
  for(var i = 0; i < tabs.length; i++) {
    tabs[i].className = '';
  }
  home.fileTab.style.display = 'none';
  home.urlTab.style.display = 'none';
  home.searchTab.style.display = 'none';
  home.terminalTab.style.display = 'none';
  e.currentTarget.className = 'active';
  var target = e.currentTarget.getAttribute('data-target');
  document.getElementById(target).style.display = 'block';
}

home.scanUrl = function(e) {
  var url = urlInput.value;
  if (!url) {
    return;
  }
  home.scanButton.innerHTML = 'Scanning url<span id="wait"></span>';
  home.scanButton.setAttribute('disabled', 1);
  var dots = window.setInterval(function() {
    var wait = document.getElementById("wait");
    if (wait.innerHTML.length > 3) {
      wait.innerHTML = "";
    }
    else {
      wait.innerHTML += ".";
    }
  }, 500);

  var postUrl = 'https://www.virustotal.com/ui/urls?url=' + url;
  request.post(postUrl, {}, function(response) {
    home.checkAnalysis(response.data.id);
  });
}

home.checkAnalysis = function(analysis_id) {
  var analysisUrl = 'https://www.virustotal.com/ui/analyses/' + analysis_id;
  request.get(analysisUrl, function(response) {
    if (!response.data.attributes.status ||
        response.data.attributes.status == 'completed') {
      document.location.href =
        appPrefix + 'url/' + response.data.meta.url_info.id;
      return;
    }

    setTimeout(function() {
      home.checkAnalysis(analysis_id);
    }, 3000);
  });
}

home.search = function(e) {
  home.searchButton.innerHTML = 'Searching<span id="searchWait"></span>';
  home.searchButton.setAttribute('disabled', 1);
  var dots = window.setInterval(function() {
    var searchWait = document.getElementById("searchWait");
    if (searchWait.innerHTML.length > 3) {
      searchWait.innerHTML = "";
    }
    else {
      searchWait.innerHTML += ".";
    }
  }, 500);
  request.get('https://www.virustotal.com/ui/search?query=' + searchInput.value,
      function(response) {
        if (!response.data.length ||
            (response.data[0].type != 'url' &&
            response.data[0].type != 'file')) {
          document.location.href = appPrefix + '404';
        } else {
          var vtObject = response.data[0];
          document.location.href =
            appPrefix + vtObject.type + '/' + vtObject.id;
        }
      });
}

home.checkInputEnterPressed = function(e, callback) {
  if (e.keyCode == 13) {
    callback();
  }
}