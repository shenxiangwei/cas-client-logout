package com.ohaotian.cas;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.jasig.cas.client.session.SessionMappingStorage;
import org.jasig.cas.client.util.AbstractConfigurationFilter;

public class SingleSignOutFilter extends AbstractConfigurationFilter {
    private static final SingleSignOutHandler handler = new SingleSignOutHandler();

    public void init(FilterConfig filterConfig) throws ServletException {
        if (!isIgnoreInitConfiguration()) {
            handler.setArtifactParameterName(getPropertyFromInitParams(filterConfig, "artifactParameterName", "ticket"));
            handler.setLogoutParameterName(getPropertyFromInitParams(filterConfig, "logoutParameterName", "logoutRequest"));
            //clusterNodeUrls
            handler.setClusterNodeUrls(getPropertyFromInitParams(filterConfig, "clusterNodeUrls", ""));
        }
        handler.init();
    }

    public void setArtifactParameterName(String name) {
        handler.setArtifactParameterName(name);
    }

    public void setLogoutParameterName(String name) {
        handler.setLogoutParameterName(name);
    }

    public void setSessionMappingStorage(SessionMappingStorage storage) {
        handler.setSessionMappingStorage(storage);
    }

    @Override
    public void doFilter(ServletRequest servletRequest,
                         ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        if (handler.isTokenRequest(request)) {
            handler.recordSession(request);
        } else if(handler.isLogoutRequest(request)){//cas-server logout请求
            handler.destroySession(request);
            return;
        } else if(handler.isLogoutRequestFromClusterNode(request)){//接收其它节点发送的http logout请求
            //清除本节点session
            handler.destroySessionFromClusterNode(request);
            return;
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {
    }

    protected static SingleSignOutHandler getSingleSignOutHandler() {
        return handler;
    }
}