(*
 * Copyright (c) 2016	Assured Information Security
 * Author Eric Chanudet <chanudete@ainfosec.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *)

type device_type = Xenfb | Inputkb
type service =
    | Surfman of (int * device_type)
    | Input of (int * device_type)

external connect : service -> Unix.file_descr
    = "stub_dmbus_connect"
external disconnect : Unix.file_descr -> unit
    = "stub_dmbus_disconnect"

type message =
    | SwitcherABS of bool
    | DeviceModelReady

external recvmsg : Unix.file_descr -> message option
    = "stub_dmbus_recvmsg"
external sendmsg : Unix.file_descr -> message -> bool
    = "stub_dmbus_sendmsg"

