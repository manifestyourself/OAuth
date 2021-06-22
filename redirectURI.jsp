<%-- 

	@(#)$Workfile: body.compensationBenefitsAndCareerAdminLoginEmulateUser.jsp $
	$Revision: 1.2 $	$Date: 2008-02-06 11:05:00 $

--%>
<%-- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - --%>

<%@page import="org.json.simple.JSONValue"%>
<%@ include file="/inc/component.inc" %>
<%@page import="sun.misc.BASE64Encoder"%>
<%@ page import="java.util.*"%>
<%@ page import="com.squareup.okhttp.*"%>
<%@page import="java.io.*"%>
<%@ page import="java.net.*"%>
<%@ page import="org.apache.commons.io.IOUtils"%>
<%@ page import="org.json.simple.*"%>
<%@ page import="java.security.MessageDigest"%>

<!-- SSO Integration for admin login H423509 -START  -->
<%
	//Getting values from properties file
	Properties propNavi = ApplicationHelper.getNaviResources();
	String token_url = propNavi.getProperty("token_url"); //https://qcwa.honeywell.com/as/token.oauth2?
	String client_id = propNavi.getProperty("client_id"); 
	String scope = propNavi.getProperty("scope"); //openid+profile+email
	String response_type = propNavi.getProperty("response_type"); //code
	String redirect_uri = propNavi.getProperty("redirect_uri"); //https://qvpa.honeywell.com/hrdirectaccess/adminLoginIdEmp.htm
	String internal_uri = propNavi.getProperty("internal_uri");
	String client_secret = propNavi.getProperty("client_secret"); 
	String grant_type = propNavi.getProperty("grant_type"); //authorization_code
	String userinfo_url = propNavi.getProperty("userinfo_url"); //userinfo endpoint
	String code_verifier = "";
	if(session.getAttribute("code_verifier") != null)
	{
		code_verifier = session.getAttribute("code_verifier").toString();
	}
	
	//Basic encoding of client id and client secret
	String headerKey = "Authorization";
	BASE64Encoder encoder = new BASE64Encoder();
	String clientidClientsecret = client_id + ":" +client_secret;
	String headerValue = "Basic " + encoder.encode(clientidClientsecret.getBytes());
	//response.setHeader("Content-Type","application/x-www-form-urlencoded; charset=utf-8");
	//response.setHeader(headerKey, headerValue);
	out.println("headerValue: " +headerValue);

	//Collecting authorization code
	String authorization_code = null;	
    if (request.getParameter("code") != null) {
    	authorization_code = request.getParameter("code");
    	out.println("Authorization code: " +authorization_code);
    }
    //authorization_code = "af8BmuCsTHx0TOWRPkZ_SapnATLlYeWlt2sAAAAC";
    
    out.println("Query string: " +request.getQueryString());
    
    //String url = token_url+"grant_type="+grant_type+"&code=" +authorization_code +"&redirect_uri=" +redirect_uri+ "&scope=" +scope+ "&code_verifier=" +code_verifier;
	//String url = "https://qcwa.honeywell.com/as/token.oauth2";			
	//out.println("Token URL: " +url);
	
	
	HttpURLConnection httpConnection = (HttpURLConnection) new URL(token_url).openConnection();
	httpConnection.setDoOutput(true); // Triggers POST.
	httpConnection.setRequestMethod("POST");
	  
	String charset = java.nio.charset.StandardCharsets.UTF_8.name();
	httpConnection.setRequestProperty("Accept-Charset", charset);
	httpConnection.setRequestProperty(headerKey, headerValue);
	httpConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=" + charset);

	String query = String.format("grant_type=%s&code=%s&redirect_uri=%s&code_verifier=%s", 
			     URLEncoder.encode(grant_type, charset),
			     URLEncoder.encode(authorization_code, charset),
			     URLEncoder.encode(redirect_uri, charset),
			     URLEncoder.encode(code_verifier, charset));
	  
	try {OutputStream output = httpConnection.getOutputStream();
	      output.write(query.getBytes(charset));
	}
	catch(Exception e) {
		out.println(e);
	}

	//System.out.println(httpConnection.getResponseCode());
	InputStream response1 = httpConnection.getInputStream();
	String result = IOUtils.toString(response1, charset);
	out.println(result);
	  
	if (result!= null) {
		Object obj=JSONValue.parse(result);    
		//creating an object of JSONObject class and casting the object into JSONObject type  
		JSONObject jsonObject = (JSONObject) obj;    
		//getting values form the JSONObject and casting that values into corresponding types  
		String access_token = (String) jsonObject.get("access_token");
		
		out.println("access_token: " +access_token);
		String query2 = String.format("access_token=%s", 
			     URLEncoder.encode(access_token, charset));
		HttpURLConnection httpConnection2 = (HttpURLConnection) new URL(userinfo_url + "?" +query2).openConnection();
		httpConnection2.setRequestProperty("Accept-Charset", charset);
		
		InputStream response2 = httpConnection2.getInputStream();
		
		try {Scanner scanner = new Scanner(response2);
		    String responseBody = scanner.useDelimiter("\\A").next();
		    out.println("Response body: " +responseBody);
		}
		catch(Exception e) {
			out.println(e);
		}
	}
	
	
	
	
	//out.println("<form id='myForm' name='myForm' action='" +url+ "' method='post'></form>");
	
	/*
	//Sending a post request to token endpoint to generate access token
	final OkHttpClient client = new OkHttpClient();
	RequestBody formBody = new FormEncodingBuilder()
      //.add("Content-Type","application/x-www-form-urlencoded")
      //.add(headerKey, headerValue)
      .add("client_id",client_id)
      .add("client_secret",client_secret)
      .add("grant_type",grant_type)
      .add("code",authorization_code)
      .add("redirect_uri",redirect_uri)
      .add("code_verifier",code_verifier)
      .build();
  Request request1 = new Request.Builder()
      .url(url)
      .header("Content-Type","application/x-www-form-urlencoded")
      .header(headerKey, headerValue)
      .post(formBody)
      .build();
  System.out.println(request1);
  Response response1 = client.newCall(request1).execute();
  System.out.println(response1.body().string());
  if (!response1.isSuccessful()) throw new IOException("Unexpected code " + response1);
  */
  
  /*
	//Code for collecting access token	
    String access_token = null;
    if(request.getParameter("access_token") != null) {
    	access_token = request.getParameter("access_token");
    	System.out.println("Access token = " +access_token);
    	response.setHeader("access_token", access_token);
    	String scriptCode = "window.location='" +token_url+ "'";
    	out.println("<script>" +scriptCode+ "</script>");
    }
    */
    /*
    String scriptCode = "window.location='" +token_url + "grant_type=" +grant_type+ "&code="+authorization_code+
    		"&redirect_uri=" +redirect_uri+ "&scope=" +scope+ "'";
    System.out.println(scriptCode);
    out.println("<script>" +scriptCode+ "</script>");
        */    
%>
<!-- SSO Integration for admin login H423509 -END  -->


