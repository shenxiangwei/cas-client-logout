package com.ohaotian.cas;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.HttpClientUtils;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.jasig.cas.client.session.HashMapBackedSessionMappingStorage;
import org.jasig.cas.client.session.SessionMappingStorage;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.util.XmlUtils;

/**
 * @author zhangwen
 * @version 0.1
 * @Description:
 * @date 2019/6/3   16:39
 * @Modify by
 */
public class SingleSignOutHandler {
    private final Log log = LogFactory.getLog(getClass());

    private SessionMappingStorage sessionMappingStorage = new HashMapBackedSessionMappingStorage();

    private String artifactParameterName = "ticket";

    private String logoutParameterName = "logoutRequest";

    private String logoutParameterClusterName = "logoutRequestCluster";
    ///clusterNodeUrls
    private String clusterNodeUrls;

    public void setSessionMappingStorage(SessionMappingStorage storage) {
        this.sessionMappingStorage = storage;
    }

    public SessionMappingStorage getSessionMappingStorage() {
        return this.sessionMappingStorage;
    }

    public void setArtifactParameterName(String name) {
        this.artifactParameterName = name;
    }

    public void setLogoutParameterName(String name) {
        this.logoutParameterName = name;
    }

    public void setClusterNodeUrls(String clusterNodeUrls) {
        this.clusterNodeUrls = clusterNodeUrls;
    }

    public void init() {
        CommonUtils.assertNotNull(this.artifactParameterName,"artifactParameterName cannot be null.");
        CommonUtils.assertNotNull(this.logoutParameterName,"logoutParameterName cannot be null.");
        CommonUtils.assertNotNull(this.sessionMappingStorage,"sessionMappingStorage cannote be null.");
    }

    public boolean isTokenRequest(HttpServletRequest request) {
        return CommonUtils.isNotBlank(CommonUtils.safeGetParameter(request,this.artifactParameterName));
    }

    public boolean isLogoutRequest(HttpServletRequest request) {
        log.info("isLogoutRequest begin----");
        log.info(request.getRequestURL());
        log.info("request.getMethod()=" + request.getMethod());
        log.info("CommonUtils.isNotBlank(CommonUtils.safeGetParameter(request, this.logoutParameterName,this.safeParameters))="
                + CommonUtils.isNotBlank(CommonUtils.safeGetParameter(request, this.logoutParameterName)));
        log.info("isLogoutRequest end----");
        return ("POST".equals(request.getMethod())) && (!isMultipartRequest(request))
                && (CommonUtils.isNotBlank(CommonUtils.safeGetParameter(request, this.logoutParameterName)));
    }

    /**
     * 判断是否是其它节点发送的logout通知
     * @param request
     * @return
     */
    public boolean isLogoutRequestFromClusterNode(HttpServletRequest request) {
        log.info("isLogoutRequestFromClusterNode begin---");
        log.info("clusterNodeUrls=" + this.clusterNodeUrls);
        log.info("request.getParameter(this.logoutParameterClusterName)=" + request.getParameter(this.logoutParameterClusterName));
        log.info("isLogoutRequestFromClusterNode end---");
        return (!isMultipartRequest(request)) && ("true".equals(request.getParameter(this.logoutParameterClusterName)));
    }

    public void recordSession(HttpServletRequest request) {
        HttpSession session = request.getSession(true);

        String token = CommonUtils.safeGetParameter(request,this.artifactParameterName);
        log.info("--------recordSession-------------token:"+token);
        if (this.log.isDebugEnabled()) {
            this.log.debug("Recording session for token " + token);
        }
        try {
            this.sessionMappingStorage.removeBySessionById(session.getId());
        } catch (Exception e) {
        }

        this.sessionMappingStorage.addSessionById(token, session);
    }

    public void destroySession(HttpServletRequest request) {
        log.info("destroySession begin---");
        String logoutMessage = CommonUtils.safeGetParameter(request,this.logoutParameterName);
        if (this.log.isTraceEnabled()) {
            this.log.trace("Logout request:\n" + logoutMessage);
        }
        String token = XmlUtils.getTextForElement(logoutMessage, "SessionIndex");
        if (CommonUtils.isNotBlank(token)) {
            HttpSession session = this.sessionMappingStorage.removeSessionByMappingId(token);

            /*if (session != null) {//session在当前节点
                log.info("destroySession session在当前节点------");
                String sessionID = session.getId();

                if (this.log.isDebugEnabled()) {
                    this.log.debug("Invalidating session [" + sessionID + "] for token [" + token + "]");
                }
                try {
                    session.invalidate();
                } catch (IllegalStateException e) {
                    this.log.debug("Error invalidating session.", e);
                }
            }else {//session不在当前节点*/
                log.info("destroySession session不在当前节点------");
                //清除其他节点，采用广播形式发送http请求
                destroySessionOfClusterNodes(token);
            //}
        }
        log.info("destroySession end---");
    }

    /**
     * 采用广播形式发送http请求,通知其他节点清除session
     * @author xubo 2018-3-21
     * @param token
     */
    private void destroySessionOfClusterNodes(String token) {
        //广播到所有节点
        log.info("destroySessionOfClusterNodes--begin-----:" + token);
        if(this.clusterNodeUrls != null && this.clusterNodeUrls.length() > 0){
            log.info(clusterNodeUrls);
            String[] clusters = this.clusterNodeUrls.split(",");
            for (String url : clusters) {
                HttpClient httpClient = new DefaultHttpClient();

                HttpPost httpPostReq = new HttpPost(url);
                List<NameValuePair> paramList = new ArrayList<NameValuePair>();
                paramList.add(new BasicNameValuePair(this.logoutParameterClusterName,"true"));
                paramList.add(new BasicNameValuePair(this.artifactParameterName,token));
                try {
                    httpPostReq.setEntity(new UrlEncodedFormEntity(paramList));
                    httpClient.execute(httpPostReq);
                } catch (Exception e) {
                    log.debug("Error destroySessionOfClusterNodes.",e);
                }finally{
                    HttpClientUtils.closeQuietly(httpClient);
                }
            }
        }
        log.info("destroySessionOfClusterNodes--end-----:" + token);
    }

    /**
     * 接收从其它节点的通知，清除session
     * @author xubo 2018-3-21
     * @param request
     */
    public void destroySessionFromClusterNode(HttpServletRequest request){
        String token = request.getParameter(this.artifactParameterName);
        log.info("destroySessionFromClusterNode----begin---:" + token);
        if(CommonUtils.isNotBlank(token)){
            final HttpSession session = sessionMappingStorage.removeSessionByMappingId(token);

            if(session != null){
                String sessionID = session.getId();

                if(log.isDebugEnabled()){
                    log.debug("Invalidating session[" + sessionID +"] for token [" + token + "]");
                }
                try {
                    session.invalidate();
                } catch (final IllegalStateException e) {
                    log.debug("Error invalidating session",e);
                }
            }
        }
        log.info("destroySessionFromClusterNode----end---:" + token);
    }

    private boolean isMultipartRequest(HttpServletRequest request) {
        return (request.getContentType() != null) && (request.getContentType().toLowerCase().startsWith("multipart"));
    }
}
