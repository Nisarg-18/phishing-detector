import streamlit as st
import pickle
from features import extract_features
import asyncio

async def main():
    st.set_page_config(
        page_title="Phishing Detector",
    )
    st.title("Phishing Classifier")

    input = st.text_input("Enter the Link")

    if st.button('Predict'):
        if(input.startswith('http')):
            final_input = await extract_features(input)    
            result =   model["model"].predict(final_input)
            if result[0] == 1:
                st.header("It is an unsafe link")
            else:
                st.header("It is a safe link")
        else:
            st.error("Please enter the complete link including http or https")
    st.caption("Please enter the full URL including http or https")

if __name__ == '__main__':
    with open('./model/model.pkl', 'rb') as file:
        model = pickle.load(file)
    asyncio.run(main())