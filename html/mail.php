<?php
session_start();
if(isset($_POST['submit']))
{
	
	 $name=$_POST['name'];
	$email=$_POST['email'];
	$message=$_POST['message'];
	//echo$to="geeta.weblance@gmail.com";
	//echo$subject="send mail";
	//echo$boday="Name:$name\n Email Id:$email\n Message:$message";
	
	//mail($to,$subject, $boday);
	
	
	
	
	$msg = '<table border="0" cellpadding="0" cellspacing="0" style="width:600px">
    <tbody>
     <tr>
      <td style="text-align:center">&nbsp;</td>
     </tr>
     <tr>
      <td style="text-align:center"><strong><img src="http://freelanceworks.in/histroy/images/logo.png"/></strong></td>
     </tr>
     <tr>
      <td>&nbsp;</td>
     </tr>
     <tr>
      <td>
      <table border="0" cellpadding="0" cellspacing="0" style="background:#4caf50; width:100%">
       <tbody>
        <tr>
         <td>&nbsp;</td>
         <td>&nbsp;</td>
         <td>&nbsp;</td>
        </tr>
        <tr>
         <td>&nbsp;</td>
         <td style="text-align:center;color:white;"><strong>Successful Primhill Computers</strong></td>
         <td style="text-align:center">&nbsp;</td>
        </tr>       
        <tr>
         <td>&nbsp;</td>
         <td>&nbsp;</td>
         <td>&nbsp;</td>
        </tr>
       </tbody>
      </table>
      </td>
     </tr>
     <tr>
      <td>
      <table border="0" cellpadding="0" cellspacing="0" style="border-bottom:1px solid #ccc; width:100%">
       <tbody>
     
        <tr>
         <td>Please find Detail </td>
         <td></td>
         <td></td>
        </tr>
        <tr>
         <td><b>Name: </b> '.$name.'</td>
         <td></td>
         <td></td>
        </tr>
        <tr>
         <td><b>Email:</b> '.$email.'</td>
         <td></td>
         <td></td>
        </tr>
		
		
		<tr>
         <td><b>message: </b> '.$message.'</td>
         <td></td>
         <td></td>
        </tr>
        
		
       
        </tbody>
      </table>
      </td>
     </tr>
    </tbody>
   </table>';


    $to="contact@primhillcomputers.com";  
    $sender_email= $email;
    $subject = "Welcome to Primhill Computers";
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";        
    $headers .= "From: ".$sender_email."\r\n";   
     
    $ok =mail($to,$subject, $msg ,$headers);
   
       if($ok==1)
			{
				$_SESSION['success']="<font color='Red'><strong>EMAIL SENT SUCCESSFULLY</strong></font>";	
			}
			else
			{
				$_SESSION['failure']="<font color='Red'><strong>EMAIL NOT SENT SUCCESSFULLY</strong></font>";
			}
			
			echo "<script type='text/javascript'>window.location='contact.php'</script>";
}
   
   ?>
   
   
   
   
	










 
 