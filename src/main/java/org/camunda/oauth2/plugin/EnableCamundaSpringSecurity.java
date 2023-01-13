package org.camunda.oauth2.plugin;

import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
@AutoConfigureOrder(Ordered.LOWEST_PRECEDENCE) //configured last
@ConditionalOnBean(type = "org.camunda.bpm.engine.ProcessEngine") //only if the ProcessEngine exists
public class EnableCamundaSpringSecurity {

    @Configuration
    @ComponentScan(basePackages = {"org.camunda.oauth2.plugin"})
    public static class ComponentScanConfiguration {
    }
}