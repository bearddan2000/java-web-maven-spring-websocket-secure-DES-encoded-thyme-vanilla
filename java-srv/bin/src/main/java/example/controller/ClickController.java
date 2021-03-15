package example.controller;

import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.stereotype.Controller;

@Controller
public class ClickController {

  @MessageMapping("/click")
  @SendTo("/topic/click")
  public example.model.Output greeting(example.model.Input clicks) throws Exception {
    if (!clicks.getIsInit()) return new example.model.Output();

    return new example.model.Output( clicks.getCount() );
  }

}
