<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%--<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>--%>
<%--<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>--%>
<html>
<head>
    <title>Title</title>
    <script src="https://apis.google.com/js/platform.js" async defer></script>
    <meta name="google-signin-client_id" content="531089080960-vu0hlmfssab5s9g3qv401dohigc1s64j.apps.googleusercontent.com">
</head>
<body>

<%--<form:form action="${pageContext}/logout" method="post">
    <form:button name="logout" value="logout"/>
</form:form>--%>

<h3>
    <a href="${request.getContextPath()}/admin">Admin Panel</a>
</h3>

<form action="${request.getContextPath()}/logout" method="post">
    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
    <button type="submit" onclick="signOut()">Log Out</button>
</form>

<script>
    function signOut() {
        var auth2 = gapi.auth2.getAuthInstance();
        auth2.signOut().then(function () {
            console.log('User signed out.');
        });
    }
</script>
</body>
</html>
