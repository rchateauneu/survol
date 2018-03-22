<?php

session_start();
?>

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <title>Contact Us</title>

    <!-- Bootstrap -->
    <link href="css/bootstrap.min.css" rel="stylesheet">
     <link href="css/font-awesome.min.css" rel="stylesheet">
     <link href="https://fonts.googleapis.com/css?family=Open+Sans:300,400,600,700" rel="stylesheet">
	 
     <link href="css/style.css" rel="stylesheet">

    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.3/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
  </head>
   <body>
<!-- ===== header start == -->
     <!--- top bar -->
     <div class="topbar thetop">
      <div class="container">
        <div class="row">
        	<div class="col-md-6 col-sm-8 col-xs-12 left-part">
            	<span class="phone"><i class="fa fa-phone"></i> <a href="tel:+447769516770" class="no-deco">+44 77 6951 6770</a></span>
                <span class="email"><i class="fa fa-envelope"></i> <a href="mailto:contact@primhillcomputers.com" class="no-deco">contact@primhillcomputers.com</a></span>
            </div>
                        <div class="col-md-6 col-sm-4 col-xs-12 right-part">
            	<ul class="hrlist social-icons">
                <li><a href="javascript:void()"><i class="fa fa-facebook"></i></a></li>
                <li><a href="javascript:void()"><i class="fa fa-twitter"></i></a></li>
                <li><a href="javascript:void()"><i class="fa fa-google-plus"></i></a></li>
                <li><a href="javascript:void()"><i class="fa fa-linkedin"></i></a></li>
                </ul>
            </div>

        </div>
      </div>
     </div>
     <!-- End -->
      <!--- navigation -->
    <div class="container">    
     <nav class="navbar navbar-default nav-def">
    		<!-- Brand and toggle get grouped for better mobile display -->
    
     <a href="index.html" class="nav-logo"><img src="images/logo.png" class="img-responsive"></a>
    
 		   <div class="navbar-header">
        <button type="button" data-target="#navbarCollapse" data-toggle="collapse" class="navbar-toggle">
            <span class="sr-only">Toggle navigation</span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
        </button>
      
       
    </div>    <!-- Collection of nav links and other content for toggling -->

    	<div id="navbarCollapse" class="collapse navbar-collapse">
       		<ul class="nav navbar-nav navbar-right pad-nav">
        <li><a href="index.html">Home</a></li>
        <li><a href="solutions.html">Solutions</a></li>
        <li><a href="survol.html">Survol</a></li>
        <li><a href="faq.html">Survol Faq</a></li>
        <li><a href="architecture.html">Survol Architecture</a></li>
        <li><a href="installation.html">Survol Installation</a></li>
        <li><a href="usecase.html">Survol Use Cases</a></li>
        <li><a href="contact.php">Contact Us</a></li>        
      </ul>
    	</div>
	</nav>
	</div>
<!-- End -->
<!-- breadcrum section -->
<div class="breadcrum-sec">
 <div class="container">
 	<div class="row">
    	<div class="col-lg-6 col-md-8 col-sm-12 col-xs-12">
        <h1 class="page-title">Contact US</h1>
        </div>
        <div class="col-lg-6 col-md-4 col-sm-12 col-xs-12">
        <ul class="breadcrumb">
<li><a href="index.html">Home</a></li>
<li class="active">Contact US</li>
</ul>
        </div>
    </div>
 </div>
</div>

<!-- ===== header-end ==== -->
<section class="map">

<iframe src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d2484.543844989843!2d-0.25561374879105103!3d51.48488677953147!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x48760e436f381f95%3A0x79baae89fd2c73dc!2sPrimhill+Computers!5e0!3m2!1sen!2sin!4v1521538379272" width="100%" height="315" frameborder="0" style="border:0" allowfullscreen></iframe>

</section>
<!-- === sections start == -->
<section class="white-sec">
<h2 class="sec-head text-center clearfix">Get <span>In Touch</span></h2>
<div class="line clearfix"><img src="images/line.png" width="71" height="4"></div>
  <div class="container contact">
    <div class="row">
     <div class="col-lg-4 col-md-4 col-sm-6 col-xs-12">
      <div class="address-box">
            <p class="sec-subhead">CONTACT INFO</p> 
          <p>+44 77 6951 6770</p>
          <p>contact@primhillcomputers.com</p>
          <p>Primhill Computers Address, 275, Boston Manor Road,
             TW8 9LG Brentford, United-Kingdom</p>
                 
          <p class="sec-subhead">SOCIAL MEDIA</p>

            <ul class="hrlist social-icons">
                <li><a href="javascript:void()" class="fb"><i class="fa fa-facebook"></i></a></li>
                <li><a href="javascript:void()" class="twiter"><i class="fa fa-twitter"></i></a></li>
                <li><a href="javascript:void()" class="gplus"><i class="fa fa-google-plus"></i></a></li>
                <li><a href="javascript:void()" class="linkedin"><i class="fa fa-linkedin"></i></a></li>
                </ul>
        </div>
     	
     </div>
     <div class="col-lg-8 col-md-8 col-sm-6 col-xs-12">
      <p class="sec-subhead">SEND YOUR MASSAGE</p>

       <?php  if(isset($_SESSION['failure'])) {echo '<div style="color:red;font-weight:bold;">'.$_SESSION['failure'].'</div>'; } unset($_SESSION['failure']);
if(isset($_SESSION['success']))
 {echo '<div style="color:#f0811a;font-weight:bold;">'.$_SESSION['success'].'</div>';} unset($_SESSION['success']);
?>


         <form class="contact-form"  method="post" action="mail.php">
          <div class="form-group">
            <input type="text" class="form-control" name="name" value="" placeholder="Name" required/>
          </div>
          <div class="form-group">
            <input type="email" class="form-control" name="email" value="" placeholder="E-mail"  required/>
          </div>
          <div class="form-group">
            <textarea class="form-control" name="message" rows="3" placeholder="Message"></textarea required/  >
          </div>
		  
		   <div class="button-field"><input type="submit" class="sub" name="submit" value="Send Message"></a></div>
          <!--<div class="button-field"><a href="javascript:void()">Send Message</a></div>-->
        </form>
     </div>    
 </div>
   </div>
</section>
       

<!-- ==== section end ==== -->

<!-- ==== Footer ==== -->
   
    <section class="footer">
    <div class="container">
    <div class="col-md-4 col-sm-4 col-xs-12">
    <div class="footer-logo"><img src="images/footer-logo.png" class="img-responsive"></div>
    </div>
      <div class="col-md-4 col-sm-4 col-xs-12">
      <div class="useful">Useful links</div>
      	<div class="row">

      <div class="col-md-6 col-sm-6 col-xs-12">
      <div class="useful-link">
      <ul>
      <li>
      <a href="index.html"><i class="fa fa-angle-right"></i> Home</a>
      </li>
      <li>
      <a href="solutions.html"><i class="fa fa-angle-right"></i> Solutions</a>
      </li>
      <li>
      <a href="survol.html"><i class="fa fa-angle-right"></i> Survol</a>
      </li>
      <li>
      <a href="faq.html"><i class="fa fa-angle-right"></i> Survol Faq</a>
      </li>
      </ul>
      </div>
      </div>
        <div class="col-md-6 col-sm-6 col-xs-12">
      <div class="useful-link">
      <ul>
      <li>
      <a href="architecture.html"><i class="fa fa-angle-right"></i> Survol Architecture</a>
      </li>
      <li>
      <a href="installation.html"><i class="fa fa-angle-right"></i> Survol Installation</a>
      </li>
      <li>
      <a href="survol.html"><i class="fa fa-angle-right"></i> Survol Use Cases</a>
      </li>
      <li>
      <a href="contact.html"><i class="fa fa-angle-right"></i> Contact Us</a>
      </li>
      </ul>
      </div>
      </div>
              </div>
      </div>
      <div class="col-md-4 col-sm-4 col-xs-12">
            <div class="contact-us">Contact us</div>
            <div class="address-map"> <i class="fa fa-map-marker"></i> Primhill Computers: 275, Boston Manor Road, TW8 9LG Brentford, United Kingdom</div>
            <div class="address-map"> <i class="fa fa-envelope"></i> Email : <a href="mailto:contact@primhillcomputers.com" class="a-link">contact@primhillcomputers.com</a></div>
            <div class="address-map"> <i class="fa fa-phone"></i> Phone Number : <a href="tel:+447769516770" class="a-link">+44 77 6951 6770</a></div>
            </div>
            </div>
    </section>
    <!-- End -->

    <div class="bottotop">
<div class='scrolltop'>
    <div class='scroll icon'><i class="fa fa-arrow-up"></i></div>
</div>
    </div>
    
    <section class="footer-bottom">
    <div class="copyright">Copyright 2018 All Right Reserved | <b>Primhill Computers</b></div>
    </section>
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="js/bootstrap.min.js"></script>
        
    <script>
    $(window).scroll(function() {
    if ($(this).scrollTop() > 50 ) {
        $('.scrolltop:hidden').stop(true, true).fadeIn();
    } else {
        $('.scrolltop').stop(true, true).fadeOut();
    }
});
$(function(){$(".scroll").click(function(){$("html,body").animate({scrollTop:$(".thetop").offset().top},"1000");return false})})
    </script>

  </body>
</html>