<%--
  ~ Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
  ~
  ~ WSO2 Inc. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>

<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.Constants" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.AuthenticationEndpointUtil" %>
<%@ page import="org.wso2.carbon.identity.captcha.util.CaptchaUtil" %>
<%@ page import="org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants" %>
<%@ page import="java.io.File" %>
<%@ page import="java.util.Map" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>

<%
    request.getSession().invalidate();
    String queryString = request.getQueryString();
    Map<String, String> idpAuthenticatorMapping = null;
    if (request.getAttribute(Constants.IDP_AUTHENTICATOR_MAP) != null) {
        idpAuthenticatorMapping = (Map<String, String>) request.getAttribute(Constants.IDP_AUTHENTICATOR_MAP);
    }

    String errorMessage = "Authentication Failed! Please Retry";
    String authenticationFailed = "false";

    if (Boolean.parseBoolean(request.getParameter(Constants.AUTH_FAILURE))) {
        authenticationFailed = "true";

        if (request.getParameter(Constants.AUTH_FAILURE_MSG) != null) {
            errorMessage = request.getParameter(Constants.AUTH_FAILURE_MSG);

            if (errorMessage.equalsIgnoreCase("authentication.fail.message")) {
                errorMessage = "Authentication Failed! Please Retry";
            }
            if (errorMessage.equalsIgnoreCase(SMSOTPConstants.TOKEN_EXPIRED_VALUE)) {
                errorMessage = "The code entered is expired. Click Resend Code to continue.";
            }
        }
    }
%>
<%
    boolean reCaptchaEnabled = false;
    if (request.getParameter("reCaptcha") != null && Boolean.parseBoolean(request.getParameter("reCaptcha"))) {
        reCaptchaEnabled = true;
    }
%>

<html>
    <head>
        <!-- header -->
        <%
            File headerFile = new File(getServletContext().getRealPath("extensions/header.jsp"));
            if (headerFile.exists()) {
        %>
        <jsp:include page="extensions/header.jsp"/>
        <% } else { %>
        <jsp:directive.include file="includes/header.jsp"/>
        <% } %>
        <!--[if lt IE 9]>
        <script src="js/html5shiv.min.js"></script>
        <script src="js/respond.min.js"></script>
        <![endif]-->
        <%
            if (reCaptchaEnabled) {
        %>
        <script src="https://recaptcha.net/recaptcha/api.js" async defer></script>
        <%
            }
        %>
        <script type="text/javascript">
            function submitForm() {
                var code = document.getElementById("OTPcode").value;
                if (code == "") {
                    document.getElementById('alertDiv').innerHTML
                        = '<div id="error-msg" class="ui negative message">Please enter the code!</div>'
                        +'<div class="ui divider hidden"></div>';
                } else {
                    if ($('#pin_form').data("submitted") === true) {
                        console.warn("Prevented a possible double submit event");
                    } else {
                        $('#pin_form').data("submitted", true);
                        $('#pin_form').submit();
                    }
                }
            }
        </script>
    </head>

    <body>
        <main class="center-segment">
            <div class="ui container medium center aligned middle aligned">
                <!-- product-title -->
                <%
                    File productTitleFile = new File(getServletContext().getRealPath("extensions/product-title.jsp"));
                    if (productTitleFile.exists()) {
                %>
                <jsp:include page="extensions/product-title.jsp"/>
                <% } else { %>
                <jsp:directive.include file="includes/product-title.jsp"/>
                <% } %>

                <div class="ui segment">
                    <!-- page content -->
                    <h2>Authenticating with SMSOTP</h2>
                    <div class="ui divider hidden"></div>
                    <%
                        if ("true".equals(authenticationFailed)) {
                    %>
                            <div class="ui negative message" id="failed-msg">
                                <%=Encode.forHtmlContent(errorMessage)%>
                            </div>
                            <div class="ui divider hidden"></div>
                    <% } %>
                    <div class="error-msg"></div>
                    <div class="segment-form">
                        <form class="ui large form" id="pin_form" name="pin_form" action="../../commonauth"  method="POST">
                            <%
                                String loginFailed = request.getParameter("authFailure");
                                if (loginFailed != null && "true".equals(loginFailed)) {
                                    String authFailureMsg = request.getParameter("authFailureMsg");
                                    if (authFailureMsg != null && "login.fail.message".equals(authFailureMsg)) {
                            %>
                                <div class="ui visible negative message">
                                    Authentication Failed! Please Retry
                                </div>
                                <div class="ui divider hidden"></div>
                            <% } }  %>
                            <!-- Token Pin -->
                            <% if (request.getParameter("screenvalue") != null) { %>
                            <div class="field">
                                <label for="password">
                                    Enter the code sent to your mobile phone:<%=Encode.forHtmlContent(request.getParameter("screenvalue"))%>
                                </label>
                                <input type="password" id='OTPcode' name="OTPcode"
                                        size='30'/>
                            <% } else { %>
                            <div class="field">
                                <label for="password">Enter the code sent to your mobile phone:</label>
                                <input type="password" id='OTPcode' name="OTPcode"
                                size='30'/>
                            <% } %>
                            </div>
                            <input type="hidden" name="sessionDataKey"
                            value='<%=Encode.forHtmlAttribute(request.getParameter("sessionDataKey"))%>'/><br/>
                            <div class="align-right buttons">
                                <div id="cancelLinkDiv" class="ui button link-button">
                                    <a id="cancle">Cancel</a>
                                </div>
                                <%
                                    if ("true".equals(authenticationFailed)) {
                                        String reSendCode = request.getParameter("resendCode");
                                        if ("true".equals(reSendCode)) {
                                %>
                                    <div id="resendCodeLinkDiv" class="ui button link-button">
                                        <a id="resend">Resend Code</a>
                                    </div>
                                <% } } %>
                                <input 
                                    type="button" name="authenticate" id="authenticate"
                                    value="Authenticate" class="ui primary button"/>
                            </div>
                            <input type='hidden' name='resendCode' id='resendCode' value='false'/>
                            <input type='hidden' name='cancelFlow' id='cancelFlow' />
                            <%
                                if (reCaptchaEnabled) {
                                    String reCaptchaKey = CaptchaUtil.reCaptchaSiteKey();
                            %>
                                <div class="field">
                                    <div class="g-recaptcha"
                                        data-sitekey="<%=Encode.forHtmlAttribute(reCaptchaKey)%>"
                                        data-testid="login-page-g-recaptcha"
                                        data-bind="authenticate"
                                        data-callback="submitForm"
                                        data-theme="light"
                                        data-tabindex="-1"
                                    >
                                    </div>
                                </div>
                            <%
                                }
                            %>
                        </form>
                    </div>
                    <div class="ui divider hidden"></div>
                    <%
                        String multiOptionURI = request.getParameter("multiOptionURI");
                        if (multiOptionURI != null && AuthenticationEndpointUtil.isValidURL(multiOptionURI)) {
                    %>
                        <a class="ui button link-button" id="goBackLink"
                        href='<%=Encode.forHtmlAttribute(multiOptionURI)%>'>
                            Choose a different authentication option
                        </a>
                    <%
                        }
                    %>
                </div>
            </div>
        </main> 
        
        <!-- product-footer -->
        <%
            File productFooterFile = new File(getServletContext().getRealPath("extensions/product-footer.jsp"));
            if (productFooterFile.exists()) {
        %>
        <jsp:include page="extensions/product-footer.jsp"/>
        <% } else { %>
        <jsp:directive.include file="includes/product-footer.jsp"/>
        <% } %>

        <!-- footer -->
        <%
            File footerFile = new File(getServletContext().getRealPath("extensions/footer.jsp"));
            if (footerFile.exists()) {
        %>
        <jsp:include page="extensions/footer.jsp"/>
        <% } else { %>
        <jsp:directive.include file="includes/footer.jsp"/>
        <% } %>

        <script type="text/javascript">
        $(document).ready(function() {
            $('#authenticate').click(function() {
                <% if (!reCaptchaEnabled) { %>
                    submitForm();
                <% } %>
            });
        });
        $(document).ready(function() {
            $('#resendCodeLinkDiv').click(function() {
                document.getElementById("resendCode").value = "true";
                $('#pin_form').submit();
            });
        });
        $(document).ready(function() {
            $('#cancelLinkDiv').click(function() {
                document.getElementById("cancelFlow").value = "true";
                $('#pin_form').submit();
            });
        });
        </script>
    </body>
</html>
