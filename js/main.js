window.onload = function() {

  var topBar = document.querySelector("#topBar");
  var pdfScreen = document.querySelector("#pdfScreen");
  var ePubScreen = document.querySelector("#readiumScreen");
  var libraryScreen = document.querySelector("#libraryScreen");
  var libraryIcon = document.querySelector("#libraryIcon");
  var ePubLogo = document.querySelector(".ePubLogo");
  var pdfLogo = document.querySelector(".PDFLogo");

  pdfScreen.style.display = "none";
  ePubScreen.style.display = "none";
  topBar.style.display = "none";
  
  

libraryIcon.addEventListener("click", function(){
    pdfScreen.style.display = "none";
    ePubScreen.style.display = "none";
    topBar.style.display = "none";
    libraryScreen.style.display = "block";
});
  
ePubLogo.addEventListener("click", function(){
    pdfScreen.style.display = "none";
    ePubScreen.style.display = "block";
    topBar.style.display = "block";
    libraryScreen.style.display = "none";
});

pdfLogo.addEventListener("click", function(){
    pdfScreen.style.display = "block";
    ePubScreen.style.display = "none";
    topBar.style.display = "block";
    libraryScreen.style.display = "none";
});
};




