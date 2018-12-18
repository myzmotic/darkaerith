/*
===========================================================================

  Copyright (c) 2010-2015 Darkstar Dev Teams

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see http://www.gnu.org/licenses/

  This file is part of DarkStar-server source code.

===========================================================================
*/

#include "../common/showmsg.h"
#include "../common/socket.h"

#include "account.h"
#include "login.h"
#include "login_auth.h"
#include "message_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <algorithm>

int32 login_fd;                 //main fd(socket) of server

/*
*
*       LOGIN SECTION
*
*/
int32 connect_client_login(int32 listenfd)
{
    int32 fd = 0;
    struct sockaddr_in client_address;
    if ((fd = connect_client(listenfd, client_address)) != -1)
    {
        create_session(fd, recv_to_fifo, send_from_fifo, login_parse);
        session[fd]->client_addr = ntohl(client_address.sin_addr.s_addr);
        return fd;
    }
    return -1;
}

int32 login_parse(int32 fd)
{
    login_session_data_t* sd = (login_session_data_t*)session[fd]->session_data;

    //check if sd will not defined
    if (sd == nullptr)
    {
        session[fd]->session_data = new login_session_data_t{};
        sd = (login_session_data_t*)session[fd]->session_data;
        sd->serviced = 0;
        login_sd_list.push_back(sd);
        sd->client_addr = session[fd]->client_addr;
        sd->login_fd = fd;
    }

    if (session[fd]->flag.eof)
    {
        do_close_login(sd, fd);
        return 0;
    }

    //all auth packets have one structure:
    // [login][password][email][sqa][sqi][code] => summary assign 131 bytes
    if (session[fd]->rdata.size() == 131)
    {
        char* buff = &session[fd]->rdata[0];

        uint8 status_code = 0x00;

        int8 code = ref<uint8>(buff, 130);
        std::string name(buff, buff + 16);
        std::string password(buff + 16, buff + 32);
        std::string email(buff + 32, buff + 64);
        std::string securityanswer(buff + 64, buff + 128);
        std::string securityid(buff + 128, buff + 130);

        char escaped_name[16 * 2 + 1];
        char escaped_pass[32 * 2 + 1];
        char escaped_email[32 * 2 + 1];
        char escaped_securityanswer[64 * 2 + 1];
        char escaped_securityid[16 * 2 + 1];

        //std::fill_n(sd->login, sizeof sd->login, '\0');
        //std::copy(name.cbegin(), name.cend(), sd->login);

        //data check
        if (check_string(name, 16) && check_string(password, 16))
        {
            ShowWarning(CL_WHITE"login_parse" CL_RESET":" CL_WHITE"%s" CL_RESET" send unreadable data\n", ip2str(sd->client_addr, nullptr));
            session[fd]->wdata.resize(1);
            ref<uint8>(session[fd]->wdata.data(), 0) = ERROR_LOGIN;
            do_close_login(sd, fd);
            return -1;
        }

        int32 ret;
        const char* fmtQuery;

        switch (code)
        {
        case SHUTDOWN:
            do_close_login(sd, fd);
            return 0;
        case LOGIN_ATTEMPT:
        {
            const char* fmtQuery = "SELECT accounts.id,accounts.status \
                                    FROM accounts \
                                    WHERE accounts.login = '%s' AND accounts.password = PASSWORD('%s')";
            Sql_EscapeString(SqlHandle, escaped_name, name.c_str());
            Sql_EscapeString(SqlHandle, escaped_pass, password.c_str());
            int32 ret = Sql_Query(SqlHandle, fmtQuery, escaped_name, escaped_pass);
            if (ret != SQL_ERROR && Sql_NumRows(SqlHandle) != 0)
            {
                ret = Sql_NextRow(SqlHandle);

                sd->accid = (uint32)Sql_GetUIntData(SqlHandle, 0);
                uint8 status = (uint8)Sql_GetUIntData(SqlHandle, 1);

                if (status & ACCST_NORMAL)
                {
                    //fmtQuery = "SELECT * FROM accounts_sessions WHERE accid = %d AND client_port <> 0";

                    //int32 ret = Sql_Query(SqlHandle,fmtQuery,sd->accid);

                    //if( ret != SQL_ERROR && Sql_NumRows(SqlHandle) != 0 )
                    //{
                    //  ref<uint8>(session[fd]->wdata,0) = 0x05; // SESSION has already activated
                    //  WFIFOSET(fd,33);
                    //  do_close_login(sd,fd);
                    //  return 0;
                    //}
                    fmtQuery = "UPDATE accounts SET accounts.timelastmodify = NULL WHERE accounts.id = %d";
                    Sql_Query(SqlHandle, fmtQuery, sd->accid);
                    fmtQuery = "SELECT charid, server_addr, server_port \
                                FROM accounts_sessions JOIN accounts \
                                ON accounts_sessions.accid = accounts.id \
                                WHERE accounts.id = %d;";
                    ret = Sql_Query(SqlHandle, fmtQuery, sd->accid);
                    if (ret != SQL_ERROR && Sql_NumRows(SqlHandle) == 1)
                    {
                        while (Sql_NextRow(SqlHandle) == SQL_SUCCESS)
                        {
                            uint32 charid = Sql_GetUIntData(SqlHandle, 0);
                            uint64 ip = Sql_GetUIntData(SqlHandle, 1);
                            uint64 port = Sql_GetUIntData(SqlHandle, 2);

                            ip |= (port << 32);

                            zmq::message_t chardata(sizeof(charid));
                            ref<uint32>((uint8*)chardata.data(), 0) = charid;
                            zmq::message_t empty(0);

                            queue_message(ip, MSG_LOGIN, &chardata, &empty);
                        }
                    }
                    memset(&session[fd]->wdata[0], 0, 33);
                    session[fd]->wdata.resize(33);
                    ref<uint8>(session[fd]->wdata.data(), 0) = SUCCESS_LOGIN;
                    ref<uint32>(session[fd]->wdata.data(), 1) = sd->accid;
                    flush_fifo(fd);
                    do_close_tcp(fd);
                }
                else if (status & ACCST_BANNED)
                {
                    memset(&session[fd]->wdata[0], 0, 33);
                    session[fd]->wdata.resize(33);
                    //  ref<uint8>(session[fd]->wdata,0) = LOGIN_SUCCESS;
                    do_close_login(sd, fd);
                }

                //////22/03/2012 Fix for when a client crashes before fully logging in:
                //              Before: When retry to login, would freeze client since login data corrupt.
                //              After: Removes older login info if a client logs in twice (based on acc id!)

                //check for multiple logins from this account id
                int numCons = 0;
                for (login_sd_list_t::iterator i = login_sd_list.begin(); i != login_sd_list.end(); ++i) {
                    if ((*i)->accid == sd->accid) {
                        numCons++;
                    }
                }

                if (numCons > 1) {
                    ShowInfo("login_parse:" CL_WHITE"<%s>" CL_RESET" has logged in %i times! Removing older logins.\n", escaped_name, numCons);
                    for (int j = 0; j < (numCons - 1); j++) {
                        for (login_sd_list_t::iterator i = login_sd_list.begin(); i != login_sd_list.end(); ++i) {
                            if ((*i)->accid == sd->accid) {
                                //ShowInfo("Current login fd=%i Removing fd=%i \n",sd->login_fd,(*i)->login_fd);
                                login_sd_list.erase(i);
                                break;
                            }
                        }
                    }
                }
                //////

                ShowInfo("login_parse:" CL_WHITE"<%s>" CL_RESET" was connected\n", escaped_name, status);
                return 0;
            }
            else {
                session[fd]->wdata.resize(1);
                ref<uint8>(session[fd]->wdata.data(), 0) = ERROR_LOGIN;
                ShowWarning("login_parse: unexisting user" CL_WHITE"<%s>" CL_RESET" tried to connect\n", escaped_name);
                do_close_login(sd, fd);
            }
        }
        break;
        case LOGIN_CREATE:
            //looking for same login
            Sql_EscapeString(SqlHandle, escaped_name, name.c_str());
            Sql_EscapeString(SqlHandle, escaped_pass, password.c_str());
            Sql_EscapeString(SqlHandle, escaped_email, email.c_str());
            Sql_EscapeString(SqlHandle, escaped_securityanswer, securityanswer.c_str());
            Sql_EscapeString(SqlHandle, escaped_securityid, securityid.c_str());
            if (Sql_Query(SqlHandle, "SELECT accounts.id FROM accounts WHERE accounts.login = '%s'", escaped_name) == SQL_ERROR)
            {
                session[fd]->wdata.resize(1);
                ref<uint8>(session[fd]->wdata.data(), 0) = ERROR_CREATE;
                return -1;
            }

            if (Sql_NumRows(SqlHandle) == 0)
            {
                //creating new account_id
                const char *fmtQuery = "SELECT max(accounts.id) FROM accounts;";

                uint32 accid = 0;

                if (Sql_Query(SqlHandle, fmtQuery) != SQL_ERROR  && Sql_NumRows(SqlHandle) != 0)
                {
                    Sql_NextRow(SqlHandle);

                    accid = Sql_GetUIntData(SqlHandle, 0) + 1;
                }
                else {
                    session[fd]->wdata.resize(1);
                    ref<uint8>(session[fd]->wdata.data(), 0) = ERROR_CREATE;
                    return -1;
                }

                accid = (accid < 1000 ? 1000 : accid);

                //creating new account
                time_t timecreate;
                tm*    timecreateinfo;

                time(&timecreate);
                timecreateinfo = localtime(&timecreate);

                char strtimecreate[128];
                strftime(strtimecreate, sizeof(strtimecreate), "%Y:%m:%d %H:%M:%S", timecreateinfo);
                fmtQuery = "INSERT INTO accounts(id,login,password,email,timecreate,timelastmodify,status,priv,sqid,sqa)\
                                       VALUES(%d,'%s',PASSWORD('%s'),'%s','%s',NULL,%d,%d,%d,PASSWORD('%s'));";

                if (Sql_Query(SqlHandle, fmtQuery, accid, escaped_name, escaped_pass, escaped_email,
                    strtimecreate, ACCST_NORMAL, ACCPRIV_USER, atoi(escaped_securityid), escaped_securityanswer) == SQL_ERROR)
                {
                    session[fd]->wdata.resize(1);
                    ref<uint8>(session[fd]->wdata.data(), 0) = ERROR_CREATE;
                    return -1;
                }

                ShowStatus(CL_WHITE"login_parse" CL_RESET": account<" CL_WHITE"%s" CL_RESET"> was created\n", escaped_name);
                session[fd]->wdata.resize(1);
                ref<uint8>(session[fd]->wdata.data(), 0) = SUCCESS_CREATE;
                ref<uint16>(session[fd]->wdata.data(), 16) = sd->accid;
                flush_fifo(fd);
                do_close_tcp(fd);
                do_close_login(sd, fd);

            }
            else {
                ShowWarning(CL_WHITE"login_parse" CL_RESET": account<" CL_WHITE"%s" CL_RESET"> already exists\n", escaped_name);
                session[fd]->wdata.resize(1);
                ref<uint8>(session[fd]->wdata.data(), 0) = ERROR_CREATE;
            }
            break;
        case LOGIN_EMAIL:

            status_code = verify_login(sd, name, password);
            if (status_code == ACCST_FAILED)
            {
                session[fd]->wdata.resize(1);
                ref<uint8>(session[fd]->wdata.data(), 0) = ERROR_LOGIN;
                ShowWarning("login_parse: unexisting user" CL_WHITE"<%s>" CL_RESET" tried to connect\n", escaped_name);
            }
            else if (status_code & ACCST_NORMAL)
            {
                Sql_EscapeString(SqlHandle, escaped_email, email.c_str());
                if (Sql_Query(SqlHandle, "UPDATE accounts SET accounts.email = '%s' WHERE accounts.id = %d", escaped_email, sd->accid) == SQL_ERROR)
                {
                    session[fd]->wdata.resize(1);
                    ref<uint8>(session[fd]->wdata.data(), 0) = ERROR_EMAIL;
                    return -1;
                }

                memset(&session[fd]->wdata[0], 0, 33);
                session[fd]->wdata.resize(33);
                ref<uint8>(session[fd]->wdata.data(), 0) = SUCCESS_EMAIL;
                flush_fifo(fd);
                do_close_tcp(fd);
                do_close_login(sd, fd);
            }
            else if (status_code & ACCST_BANNED)
            {
                memset(&session[fd]->wdata[0], 0, 33);
                session[fd]->wdata.resize(33);
            }
            break;
        case LOGIN_PASS:

            status_code = verify_login(sd, name, password);
            if (status_code == ACCST_FAILED)
            {
                session[fd]->wdata.resize(1);
                ref<uint8>(session[fd]->wdata.data(), 0) = ERROR_LOGIN;
                ShowWarning("login_parse: unexisting user" CL_WHITE"<%s>" CL_RESET" tried to connect\n", escaped_name);
            }
            else if (status_code & ACCST_NORMAL)
            {
                Sql_EscapeString(SqlHandle, escaped_pass, password.c_str());
                Sql_EscapeString(SqlHandle, escaped_email, email.c_str()); // This is actually the new password
                if (Sql_Query(SqlHandle, "UPDATE accounts SET accounts.password = PASSWORD('%s') WHERE accounts.id = %d", escaped_email, sd->accid) == SQL_ERROR)
                {
                    session[fd]->wdata.resize(1);
                    ref<uint8>(session[fd]->wdata.data(), 0) = ERROR_PASS;
                    return -1;
                }

                memset(&session[fd]->wdata[0], 0, 33);
                session[fd]->wdata.resize(33);
                ref<uint8>(session[fd]->wdata.data(), 0) = SUCCESS_PASS;
                flush_fifo(fd);
                do_close_tcp(fd);
                do_close_login(sd, fd);

            }
            else if (status_code & ACCST_BANNED)
            {
                memset(&session[fd]->wdata[0], 0, 33);
                session[fd]->wdata.resize(33);
                do_close_login(sd, fd);
            }
        case LOGIN_SEC_CODE:

            status_code = verify_login(sd, name, password);
            if (status_code == ACCST_FAILED)
            {
                session[fd]->wdata.resize(1);
                ref<uint8>(session[fd]->wdata.data(), 0) = ERROR_LOGIN;
                ShowWarning("login_parse: unexisting user" CL_WHITE"<%s>" CL_RESET" tried to connect\n", escaped_name);
            }
            else if (status_code & ACCST_NORMAL)
            {
                Sql_EscapeString(SqlHandle, escaped_securityanswer, securityanswer.c_str());
                Sql_EscapeString(SqlHandle, escaped_securityid, securityid.c_str());

                if (Sql_Query(SqlHandle, "UPDATE accounts SET accounts.sqa = PASSWORD('%s'), accounts.sqid = '%d' WHERE accounts.id = %d", escaped_securityanswer, atoi(escaped_securityid), sd->accid) == SQL_ERROR)
                {
                    session[fd]->wdata.resize(1);
                    ref<uint8>(session[fd]->wdata.data(), 0) = ERROR_SEC_CODE;
                    return -1;
                }

                memset(&session[fd]->wdata[0], 0, 33);
                session[fd]->wdata.resize(33);
                ref<uint8>(session[fd]->wdata.data(), 0) = SUCCESS_SEC_CODE;
                flush_fifo(fd);
                do_close_tcp(fd);
                do_close_login(sd, fd);

            }
            else if (status_code & ACCST_BANNED)
            {
                memset(&session[fd]->wdata[0], 0, 33);
                session[fd]->wdata.resize(33);
                do_close_login(sd, fd);
            }
            break;
        case LOGIN_RECOVER:
      
            fmtQuery = "SELECT accounts.id,accounts.status,accounts.sqid \
                                    FROM accounts \
                                    WHERE accounts.login = '%s'";
            Sql_EscapeString(SqlHandle, escaped_name, name.c_str());
            ret = Sql_Query(SqlHandle, fmtQuery, escaped_name);
            if (ret != SQL_ERROR && Sql_NumRows(SqlHandle) != 0)
            {
                ret = Sql_NextRow(SqlHandle);

                sd->accid = (uint32)Sql_GetUIntData(SqlHandle, 0);
                uint8 status = (uint8)Sql_GetUIntData(SqlHandle, 1);
                uint32 sqid = (uint32)Sql_GetUIntData(SqlHandle, 2);

                if (status & ACCST_NORMAL)
                {
                    memset(&session[fd]->wdata[0], 0, 33);
                    session[fd]->wdata.resize(33);
                    ref<uint8>(session[fd]->wdata.data(), 0) = SUCCESS_USERFOUND;
                    ref<uint16>(session[fd]->wdata.data(), 16) = sqid;
                    flush_fifo(fd);
                    do_close_tcp(fd);
                    do_close_login(sd, fd);

                }
                else if (status & ACCST_BANNED)
                {
                    memset(&session[fd]->wdata[0], 0, 33);
                    session[fd]->wdata.resize(33);
                    //  ref<uint8>(session[fd]->wdata,0) = LOGIN_SUCCESS;
                    do_close_login(sd, fd);
                }

                return 0;
            }
            else {
                session[fd]->wdata.resize(1);
                ref<uint8>(session[fd]->wdata.data(), 0) = ERROR_USERFOUND;
                ShowWarning("login_parse: unexisting user" CL_WHITE"<%s>" CL_RESET" tried to connect\n", escaped_name);
            }
            break;
        case LOGIN_SQATTEMPT:

            Sql_EscapeString(SqlHandle, escaped_name, name.c_str());
            Sql_EscapeString(SqlHandle, escaped_securityanswer, securityanswer.c_str());
            Sql_EscapeString(SqlHandle, escaped_securityid, securityid.c_str());
            if (Sql_Query(SqlHandle, "SELECT *  FROM accounts WHERE accounts.login = '%s' AND accounts.sqa = PASSWORD('%s') AND accounts.sqid = '%d'", escaped_name, escaped_securityanswer, atoi(escaped_securityid)) == SQL_ERROR)
            {
                session[fd]->wdata.resize(1);
                ref<uint8>(session[fd]->wdata.data(), 0) = ERROR_SQFAILED;
                return -1;
            }

            if (Sql_NumRows(SqlHandle) > 0)
            {
                memset(&session[fd]->wdata[0], 0, 33);
                session[fd]->wdata.resize(33);
                ref<uint8>(session[fd]->wdata.data(), 0) = SUCCESS_SQCHANGED;
                flush_fifo(fd);
                do_close_tcp(fd);

                return 0;
            }
            else {
                session[fd]->wdata.resize(1);
                ref<uint8>(session[fd]->wdata.data(), 0) = ERROR_SQFAILED;
                ShowWarning("login_parse: unexisting user" CL_WHITE"<%s>" CL_RESET" tried to connect\n", escaped_name);
            }
            break;
        default:
            ShowWarning("login_parse: undefined code:[%d], ip sender:<%s>\n", code, ip2str(session[fd]->client_addr, nullptr));
            break;
        };
        //RFIFOSKIP(fd,33);
    }
    else {
        do_close_login(sd, fd);
    }
    return 0;
};

int32 do_close_login(login_session_data_t* loginsd, int32 fd)
{
    ShowInfo(CL_WHITE"login_parse" CL_RESET":" CL_WHITE"%s" CL_RESET"shutdown socket...\n", ip2str(loginsd->client_addr, nullptr));
    erase_loginsd(fd);
    do_close_tcp(fd);
    return 0;
}

bool check_string(std::string const& str, std::size_t max_length)
{
    return !str.empty() && str.size() <= max_length && std::all_of(str.cbegin(), str.cend(), [](char const& c) { return c >= 0x20; });
}

uint8 verify_login(login_session_data_t* sd, std::string name, std::string password)
{
    char escaped_name[16 * 2 + 1];
    char escaped_pass[32 * 2 + 1];

    const char* fmtQuery = "SELECT accounts.id,accounts.status \
                                    FROM accounts \
                                    WHERE accounts.login = '%s' AND accounts.password = PASSWORD('%s')";
    Sql_EscapeString(SqlHandle, escaped_name, name.c_str());
    Sql_EscapeString(SqlHandle, escaped_pass, password.c_str());
    int32 ret = Sql_Query(SqlHandle, fmtQuery, escaped_name, escaped_pass);
    uint8 status = ACCST_FAILED;
    if (ret != SQL_ERROR && Sql_NumRows(SqlHandle) != 0)
    {
        ret = Sql_NextRow(SqlHandle);

        sd->accid = (uint32)Sql_GetUIntData(SqlHandle, 0);
        status = (uint8)Sql_GetUIntData(SqlHandle, 1);

        //////22/03/2012 Fix for when a client crashes before fully logging in:
        //              Before: When retry to login, would freeze client since login data corrupt.
        //              After: Removes older login info if a client logs in twice (based on acc id!)

        //check for multiple logins from this account id
        int numCons = 0;
        for (login_sd_list_t::iterator i = login_sd_list.begin(); i != login_sd_list.end(); ++i) {
            if ((*i)->accid == sd->accid) {
                numCons++;
            }
        }

        if (numCons > 1) {
            ShowInfo("login_parse:" CL_WHITE"<%s>" CL_RESET" has logged in %i times! Removing older logins.\n", escaped_name, numCons);
            for (int j = 0; j < (numCons - 1); j++) {
                for (login_sd_list_t::iterator i = login_sd_list.begin(); i != login_sd_list.end(); ++i) {
                    if ((*i)->accid == sd->accid) {
                        //ShowInfo("Current login fd=%i Removing fd=%i \n",sd->login_fd,(*i)->login_fd);
                        login_sd_list.erase(i);
                        break;
                    }
                }
            }
        }
    }

    return status;
}