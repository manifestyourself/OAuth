<%-- 

	@(#)$Workfile: body.compensationBenefitsAndCareerAdminLogin.jsp $
	$Revision: 1.2 $	$Date: 2008-02-06 11:05:00 $

--%>
<%-- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - --%>

<%@ include file="/inc/component.inc" %>
<%@ page import="java.util.Properties"%>
<%@ page import="java.security.*"%>
<%@ page import="org.apache.commons.codec.binary.Base64"%>




<!-- SSO Integration for admin login H423509 -START -->
<%
		//Getting details from properties file
		Properties propNavi = ApplicationHelper.getNaviResources();
		String authorization_url = propNavi.getProperty("authorization_url"); //https://qcwa.honeywell.com/as/authorization.oauth2?
		String client_id = propNavi.getProperty("client_id"); 
		String scope = propNavi.getProperty("scope"); //openid+profile+email
		String response_type = propNavi.getProperty("response_type"); //code
		String redirect_uri = propNavi.getProperty("redirect_uri"); //https://qvpa.honeywell.com/hrdirectaccess/adminLoginIdEmp.htm
		String internal_uri = propNavi.getProperty("internal_uri");
		String client_secret = propNavi.getProperty("client_secret"); 
		String grant_type = propNavi.getProperty("grant_type"); //authorization_code
		
		
    	//Hash code_verifier to create code_challenge
		// Dependency: Apache Commons Codec
		// https://commons.apache.org/proper/commons-codec/
		// Import the Base64 class.
		// import org.apache.commons.codec.binary.Base64;
		//Generate code_verifier		
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "abcdefghijklmnopqrstuvxyz";
        StringBuilder sb = new StringBuilder(44); 
  
        for (int i = 0; i < 44; i++) { 
              int index = (int)(AlphaNumericString.length() * Math.random()); 
            sb.append(AlphaNumericString.charAt(index)); 
        }
        String code_verifier = sb.toString();
        
      //Hash code_verifier to create code_challenge

    	MessageDigest digest = MessageDigest.getInstance("SHA-256");
    	byte[] encodedhash = digest.digest(code_verifier.getBytes(java.nio.charset.StandardCharsets.UTF_8.name()));
    	StringBuilder hexString = new StringBuilder(2 * encodedhash.length);
        for (int i = 0; i < encodedhash.length; i++) {
            String hex = Integer.toHexString(0xff & encodedhash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        //String code_challenge = hexString.toString();
       
        String code_challenge = code_verifier;
        System.out.println("code_challenge: " +code_challenge);
        session.setAttribute("code_verifier", code_verifier);
        
        String code_challenge_method = "plain";
        
		
        //scriptcode with code_challenge
		String scriptCode = "window.location='" +authorization_url+ "client_id=" +client_id+ "&scope=" +scope+ "&response_type=" +response_type+ "&redirect_uri=" +redirect_uri+ "&code_challenge=" +code_challenge+ "&code_challenge_method=" +code_challenge_method +"';";
		
		//scriptCode withtout code_challenge
		//String scriptCode = "window.location='" +authorization_url+ "client_id=" +client_id+ "&scope=" +scope+ "&response_type=" +response_type+ "&redirect_uri=" +redirect_uri+ "';";
		System.out.println(scriptCode);
		//out.println("<script>" +scriptCode+ "</script>");
		//window.location="https://qcwa.honeywell.com/as/authorization.oauth2?client_id=Client_49022&scope=openid+profile+email&response_type=code&redirect_uri=http://10.224.89.48:8081/hrdirectaccess/adminLoginIdEmp.htm";		
		
%>
<!-- SSO Integration for admin login H423509 -END  -->

