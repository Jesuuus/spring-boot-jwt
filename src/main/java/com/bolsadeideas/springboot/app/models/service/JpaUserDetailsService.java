package com.bolsadeideas.springboot.app.models.service;

import com.bolsadeideas.springboot.app.models.dao.IUsuarioDao;
import com.bolsadeideas.springboot.app.models.entity.Rol;
import com.bolsadeideas.springboot.app.models.entity.Usuario;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service("jpaUserDetailService")
public class JpaUserDetailsService implements UserDetailsService {

    @Autowired
    private IUsuarioDao usuarioDao;

    private Logger logger = LoggerFactory.getLogger(JpaUserDetailsService.class);

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Usuario usuario = usuarioDao.findByUsername(username);

        if(usuario == null) {
            logger.error("Error login: no exixste el usuario".concat(username));
            throw  new UsernameNotFoundException("Username".concat(username).concat("no existe"));
        }

        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        for (Rol rol:usuario.getRoles()){
            authorities.add(new SimpleGrantedAuthority(rol.getAuthority()));
        }

        if(authorities.isEmpty()) {
            logger.error("Error login: usuario".concat(username).concat("no tiene roles asignados"));
            throw  new UsernameNotFoundException("Error login: usuario".concat(username).concat("no tiene roles asignados"));
        }

        return new User(username,usuario.getPassword(),usuario.isEnabled(),true,true,true,authorities);
    }
}
