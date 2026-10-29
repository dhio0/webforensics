<?php
function current_user_row()
{
    $q = "SELECT * FROM accounts WHERE login = '" . $_COOKIE['login'] . "'"; // vuln
    return mysql_query($q);
}
