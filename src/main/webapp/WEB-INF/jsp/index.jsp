<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<html>
<head>
    <title>Title</title>
</head>
<body>

<%--<form:form autocomplete="false" method="post" action="${pageContext}/login" modelAttribute="user">
    <form:input path="username" />
    <form:input path="password" />
    <form:button name="login" value="Log in"/>
</form:form>--%>

<form method="post" action="${request.getContextPath()}/login" >
    <label>Username
        <input name="username" type="text">
    </label>
    <label>Password
        <input type="password" name="password">
    </label>

    <button type="submit">Log in</button>
</form>

</body>
</html>
