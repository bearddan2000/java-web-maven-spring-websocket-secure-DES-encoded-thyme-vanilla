package example.model;

public class Input {

  private boolean isInit;
  private int count;

  public Input(int count, boolean isInit) {
    this.count = count;
    this.isInit = isInit;
  }

  public int getCount() {
    return this.count;
  }

  public boolean getIsInit() {
    return this.isInit;
  }
}
