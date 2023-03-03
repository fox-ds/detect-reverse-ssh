@load base/protocols/ssh
@load base/frameworks/notice

module SSH;

export {
	redef enum Notice::Type += {
		Reverse_SSH,
	};
}

event ssh2_ecc_init(c: connection, is_orig: bool) {
    if ( ! is_orig ) {
        NOTICE([$note=Reverse_SSH,
                $msg="Reverse SSH session observed based on SSH2_ECC_INIT from TCP server"]);
    }
}

event ssh2_dh_gex_init(c: connection, is_orig: bool) {
    if ( ! is_orig ) {
        NOTICE([$note=Reverse_SSH,
                $msg="Reverse SSH session observed based on SSH2_DH_GEX_INIT from TCP server"]);
    }
}

event ssh2_gss_init(c: connection, is_orig: bool) {
    if ( ! is_orig ) {
        NOTICE([$note=Reverse_SSH,
                $msg="Reverse SSH session observed based on SSH2_GSS_INIT from TCP server"]);
    }
}

event ssh2_rsa_secret(c: connection, is_orig: bool) {
    if ( ! is_orig ) {
        NOTICE([$note=Reverse_SSH,
                $msg="Reverse SSH session observed based on SSH2_RSA_SECRET from TCP server"]);
    }
}
