
import pandas as pd
from sqlalchemy import create_engine

# Load CSV data
file_path = '/workspace/workspace/user_1/raphy_20250517144429.csv'
data = pd.read_csv(file_path)

# Handle missing values
data.fillna({
    'Age': data['Age'].median(),
    'JobSatisfaction': data['JobSatisfaction'].mode()[0],
    'RelationshipSatisfaction': data['RelationshipSatisfaction'].mode()[0],
    'OverTime': False  # Assuming no overtime if missing
}, inplace=True)

# Create SQLite engine
engine_path = '/workspace/workspace/user_1/database.db'
engine = create_engine(f'sqlite:///{engine_path}')

# Prepare fact table
fact_employee_metrics = data[['EmployeeNumber', 'Age', 'DailyRate',
                               'DistanceFromHome', 'MonthlyIncome',
                               'YearsAtCompany', 'JobSatisfaction',
                               'RelationshipSatisfaction',
                               'PerformanceRating', 'TrainingTimesLastYear']]

# Prepare dimension tables
dim_employee = data[['EmployeeNumber', 'Gender', 'MaritalStatus', 
                     'Over18', 'OverTime', 'JobRole', 'Department']].drop_duplicates()

dim_business_travel = data[['BusinessTravel']].drop_duplicates()
dim_education = data[['Education', 'EducationField']].drop_duplicates()

# Write tables into SQLite database
fact_employee_metrics.to_sql('fact_employee_metrics', engine, index=False, if_exists='replace')
dim_employee.to_sql('dim_employee', engine, index=False, if_exists='replace')
dim_business_travel.to_sql('dim_business_travel', engine, index=False, if_exists='replace')
dim_education.to_sql('dim_education', engine, index=False, if_exists='replace')

print("Data ETL process completed successfully.")
