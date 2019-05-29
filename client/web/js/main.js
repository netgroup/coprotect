$(document).ready(function(){
  Dropzone.options.myAwesomeDropzone = { // The camelized version of the ID of the form element
    // The configuration we've talked about above
    url: '#',
    previewsContainer: ".dropzone-previews",
    uploadMultiple: true,
    parallelUploads: 100,
    maxFiles: 100,
    accept: function(file, done) {
	    if (file.name == "justinbieber.jpg") {
	      done("Naha, you don't.");
	    }
	    else { done(); }
	  }
  }

});
