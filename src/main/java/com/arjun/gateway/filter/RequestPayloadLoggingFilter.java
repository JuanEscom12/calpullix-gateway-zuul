package com.arjun.gateway.filter;

import javax.servlet.http.HttpServletRequest;

import org.apache.tomcat.util.json.JSONParser;
import org.springframework.stereotype.Component;

import com.google.common.io.CharStreams;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.http.HttpServletRequestWrapper;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class RequestPayloadLoggingFilter extends ZuulFilter {
	
		private static final String PREFIX_PRE = "pre";
	
		@Override
	    public String filterType() {
	        return PREFIX_PRE;
	    }

	    @Override
	    public int filterOrder() {
	        return 3;
	    }

	    @Override
	    public boolean shouldFilter() {
	        return true;
	    }

	    @Override
	    public Object run() {
	        RequestContext ctx = RequestContext.getCurrentContext();
	        HttpServletRequest request = new HttpServletRequestWrapper(ctx.getRequest());
	        log.info(":: Request to Method: {} URL: {} ", request.getMethod(), request.getRequestURL());
	        String requestData = null;
	        JSONParser jsonParser = null;
	        try {
	            if (request.getContentLength() > 0) {
	                requestData = CharStreams.toString(request.getReader());
	            }
	            if (requestData == null) {
	                return null;
	            }
	            jsonParser = new JSONParser(requestData);
	            log.info(String.format("%s request payload %s", request.getMethod(), jsonParser.parse()));
	        } catch (Exception e) {
	            log.error("Error parsing JSON request", e);
	            return null;
	        }
	        return null;
	    }
	
}
