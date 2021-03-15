package example.model;

import java.util.*;
import java.text.SimpleDateFormat;

public class Output {
  private static Map<Long, String> content;
  private static int count;

  public Output() {
    if (content == null) {
      Output.content = new HashMap<>();
    }
  }

  public Output(int count) {
    Output.count = count+1;
  }

  public int getCount() {
    return Output.count;
  }

  private void insertTime(){
    Calendar calendar = Calendar.getInstance();
    //Returns current time in millis
    Long key = new Long(calendar.getTimeInMillis());

    String time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(calendar.getTime());

    if (!Output.content.containsKey(key))
        Output.content.put(key, "Last click was: " + time);
  }

  private ArrayList<String> createContent() {
    ArrayList<String> result = new ArrayList<String>();

    List<Long> sortedKeys=new ArrayList<Long>(Output.content.keySet());
    Collections.sort(sortedKeys);

    for ( Long k : sortedKeys)
      result.add(Output.content.get(k));

    return result;
  }

  public ArrayList<String> getContent() {
    insertTime();
    return createContent();
  }

}
