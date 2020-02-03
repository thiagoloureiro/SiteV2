function getCookie(name) {
  var value = "; " + document.cookie;
  var parts = value.split("; " + name + "=");
  if (parts.length == 2) return parts.pop().split(";").shift();
}
function getAvDomRow(result) {
  var row = '<tr class=' + result.category + '>';
  row += '<td>' + result.name + '</td>';
  row += '<td>' + result.category + '</td>';
  if (result.update) {
    row += '<td>' + result.update + '</td>';
  }
  row += '</tr>';
  return row;
}
function resultToArraySorted(analysisResults) {
  var results = [];
  var keys = Object.keys(analysisResults);

  // Convert results to array
  // Sort by detected/undetected -> alphabetical
  for (var i = 0; i < keys.length; i++) {
    results.push({
      name: keys[i],
      category: analysisResults[keys[i]].category,
      update: analysisResults[keys[i]].engine_update,
    });
  }

  results = results.sort(function(a, b) {
    if (a.category == b.category) {
      return 0;
    }

    if (a.category == 'malicious') {
      return -1;
    }

    if (a.category == 'undetected' && (b.category != 'malicious' &&
      b.category != 'undetected')) {
      return -1;
    }
  });

  return results;
}
function getUrlVars() {
  var vars = {};
  var parts = window.location.href.replace(/[?&]+([^=&]+)=([^&]*)/gi,
      function(m,key,value) {
    vars[key] = value;
  });
  return vars;
}
function getUrlParam(parameter, defaultvalue){
  var urlparameter = defaultvalue;
  if (window.location.href.indexOf(parameter) > -1) {
    urlparameter = getUrlVars()[parameter];
  }
  return urlparameter;
}

/**
 * AJAX Wrapper
 */
var request = {};
/**
 * Get request
 * @param  {String}   url      Url
 * @param  {Function} callback Callback function
 * @param  {Function} error    Error callback function
 */
request.get = function(url, callback, error) {
  request._generateRequest('GET', url, null, callback, error);
}
/**
 * Post request
 * @param  {String}   url      Url
 * @param  {Object}   data     Post data
 * @param  {Function} callback Callback function
 * @param  {Function} error    Error callback function
 */
request.post = function(url, data, callback, error) {
  request._generateRequest('POST', url, data, callback, error);
}
/**
 * File upload request
 * @param  {String}   url      Url
 * @param  {Object}   file     File object
 * @param  {Function} callback Callback function
 * @param  {Function} error    Error callback function
 */
request.postFile = function(url, file, callback, error) {
  var formData = new FormData();
  formData.append('file', file, file.name);
  formData.append('item', file.id);


  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
      this.response;
      if (callback) {
        callback(this.response);
      }
    } else if(this.readyState == 4 && error) {
      error(this.response);
    }
  };
  xhttp.open('POST', url, true);
  xhttp.setRequestHeader('X-Session-Hash', getCookie('VT_SESSION_HASH'));
  xhttp.withCredentials = true;
  xhttp.responseType = 'json';
  xhttp.send(formData);
}
request._generateRequest = function(method, url, data, callback, error) {
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
      if (callback) {
        callback(JSON.parse(this.response));
      }
    } else if(this.readyState == 4 && error) {
      error(JSON.parse(this.response));
    }
  };
  xhttp.open(method, url, true);
  xhttp.setRequestHeader('content-type', 'application/json; charset=utf-8');
  xhttp.setRequestHeader('X-Session-Hash', getCookie('VT_SESSION_HASH'));
  xhttp.withCredentials = true;
  xhttp.send();
}