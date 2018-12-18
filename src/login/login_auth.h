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

#ifndef _LOGIN_AUTH_H
#define _LOGIN_AUTH_H

#include "../common/cbasetypes.h"

#include "login_session.h"

/*==========================================
* Login-Server data parse
*-------------------------------------------*/
#define LOGIN_ATTEMPT      0x10
#define LOGIN_CREATE       0x20
#define LOGIN_EMAIL        0x30
#define LOGIN_PASS         0x40
#define LOGIN_SEC_CODE	   0x50
#define LOGIN_RECOVER      0x60
#define LOGIN_SQATTEMPT    0x70

#define SUCCESS_LOGIN      0x01
#define SUCCESS_CREATE     0x02
#define SUCCESS_EMAIL      0x03
#define SUCCESS_PASS       0x04
#define SUCCESS_SEC_CODE   0x05

#define ERROR_LOGIN        0x06
#define ERROR_CREATE       0x07
#define ERROR_EMAIL        0x08
#define ERROR_PASS         0x09
#define ERROR_SEC_CODE	   0x10

#define SUCCESS_USERFOUND  0x11
#define ERROR_USERFOUND    0x12

#define SUCCESS_SQCHANGED  0x13
#define ERROR_SQFAILED     0x14

#define SHUTDOWN           0x15

extern int32 login_fd;
/*
*
*   Parse connections for authentification
*/
int32 connect_client_login(int32 listenfd);


int32 login_parse(int32 fd);

bool check_string(std::string const& str, std::size_t max_length);
uint8 verify_login(login_session_data_t* sd, std::string name, std::string password);

/*=============================================
* login data close socket
*-------------------------------------------*/
int32 do_close_login(login_session_data_t *loginsd, int32 fd);
#endif