$(function () {

	var viewerElement = document.getElementById('indexViewer');
	var myWebViewer = new PDFTron.WebViewer({
		type: "html5",
		path: "lib",
		documentType: "pdf",
		pdfBackend: 'pnacl',
		showLocalFilePicker: true,
		enableAnnotations: true
	}, viewerElement);

});