// Android/iOS shell: loads the Signet web app. Replace WEB_URL with your Pxxl address.
import { SafeAreaView, StatusBar } from "react-native";
import { WebView } from "react-native-webview";

const WEB_URL = "https://your-app.pxxl.pro";

export default function App() {
  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: "#ffffff" }}>
      <StatusBar barStyle="dark-content" />
      <WebView source={{ uri: WEB_URL }} style={{ flex: 1 }} setSupportMultipleWindows={false} />
    </SafeAreaView>
  );
}
