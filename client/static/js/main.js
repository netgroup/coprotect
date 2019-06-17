//$(document).ready(function(){

    Dropzone.options.encryptDropzone = {
            paramName: "file",
            maxFilesize: 10,
            url: '/crypto/encrypt',
            previewsContainer: "#encrypt-dropzone-previews",
            uploadMultiple: true,
            parallelUploads: 5,
            maxFiles: 20,
            init: function() {
                var cd;
                this.on("success", function(file, response) {
                    $('.dz-progress').hide();
                    $('.dz-size').hide();
                    $('.dz-error-mark').hide();
                    console.log(response);
                    console.log(file);
                    cd = response;
                });
                this.on("sending", function(file, xhr, o) {
                  console.log(file);
                });

                this.on("drop", function (file) {
                  formdata = new FormData();
                  if($(this).prop('files').length > 0) {
                    file = $(this).prop('files')[0];
                    formdata.append("file", file);
                  };
                  $.ajax({
                    type: 'POST',
                    url: '/crypto/encrypt',
                    data: formdata,
                    processData: false,
                    contentType: false,
                    success: function (result) {
                         // if all is well
                         // play the audio file
                    }
                  });
                });

                this.on("complete", function(file, resp) {
                  console.log(resp);
                });
                this.on("addedfile", function(file) {
                    var removeButton = Dropzone.createElement("<a href=\"#\">Remove file</a>");
                    var _this = this;
                    removeButton.addEventListener("click", function(e) {
                        e.preventDefault();
                        e.stopPropagation();
                        _this.removeFile(file);
                        var name = "largeFileName=" + cd.pi.largePicPath + "&smallFileName=" + cd.pi.smallPicPath;
                        $.ajax({
                            type: 'POST',
                            url: 'DeleteImage',
                            data: name,
                            dataType: 'json'
                        });
                    });
                    file.previewElement.appendChild(removeButton);
                });
            }
    };

    Dropzone.options.decryptDropzone = {
            paramName: "file",
            maxFilesize: 10,
            url: '/crypto/decrypt',
            previewsContainer: "#decrypt-dropzone-previews",
            uploadMultiple: true,
            parallelUploads: 5,
            maxFiles: 20,
            init: function() {
                var cd;
                this.on("success", function(file, response) {
                    $('.dz-progress').hide();
                    $('.dz-size').hide();
                    $('.dz-error-mark').hide();
                    console.log(response);
                    console.log(file);
                    cd = response;
                });
                this.on("sending", function(file, xhr, o) {
                  console.log(file);
                });

                this.on("drop", function (file) {
                  formdata = new FormData();
                  if($(this).prop('files').length > 0) {
                    file = $(this).prop('files')[0];
                    formdata.append("file", file);
                  };
                  $.ajax({
                    type: 'POST',
                    url: '/crypto/decrypt',
                    data: formdata,
                    processData: false,
                    contentType: false,
                    success: function (result) {
                         // if all is well
                         // play the audio file
                    }
                  });
                });

                this.on("complete", function(file, resp) {
                  console.log(resp);
                });
                this.on("addedfile", function(file) {
                    var removeButton = Dropzone.createElement("<a href=\"#\">Remove file</a>");
                    var _this = this;
                    removeButton.addEventListener("click", function(e) {
                        e.preventDefault();
                        e.stopPropagation();
                        _this.removeFile(file);
                        var name = "largeFileName=" + cd.pi.largePicPath + "&smallFileName=" + cd.pi.smallPicPath;
                        $.ajax({
                            type: 'POST',
                            url: 'DeleteImage',
                            data: name,
                            dataType: 'json'
                        });
                    });
                    file.previewElement.appendChild(removeButton);
                });
            }
    };

//});

document.getElementById('show-log').addEventListener('click', function() {
    var currDisplay = document.getElementById('log').style.display;
    if (currDisplay == 'block') {
      document.getElementById('log-label').style.display = 'none';
      document.getElementById('log').style.display = 'none';
    } else {
      document.getElementById('log-label').style.display = 'block';
      document.getElementById('log').style.display = 'block';
    }
    
});
